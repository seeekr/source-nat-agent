package main

import (
	"fmt"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/exec"
	"time"
)

func init() {
	// not sure it's wise to remove the iptables rules while traffic is happening
	// it would be smarter, on init, to:
	// - ensure chain exists
	// - load all rules on that chain
	// - get all pods and namespaces from k8s, decide which rules to drop or add
	// - then continue to watch resources
	// in that way, we could make sure that there was never a time when live traffic would be handled differently
	// than what this agent is set up to ensure

	terminate()
	shell("iptables -w -t nat -N SOURCE-NAT-AGENT")
	shell("iptables -w -t nat -I POSTROUTING -j SOURCE-NAT-AGENT")
	shell("iptables -w -t nat -A SOURCE-NAT-AGENT \\! -s 10.42.0.0/16 -j RETURN")
	shell("iptables -w -t nat -A SOURCE-NAT-AGENT -d 10.42.0.0/16 -j RETURN")

	// probably also not smart to remove all rules when we're shutting down
	// I'm assuming this is here for debugging purposes
	// should likely be removed for proper production usage
	defer terminate()
}

func terminate() {
	shell("iptables -w -t nat -D POSTROUTING -j SOURCE-NAT-AGENT 2>/dev/null ||:")
	shell("iptables -w -t nat -F SOURCE-NAT-AGENT 2>/dev/null ||:")
	shell("iptables -w -t nat -X SOURCE-NAT-AGENT 2>/dev/null ||:")
}

func cleanRule(id string) {
	shell(`iptables -w -t nat -S SOURCE-NAT-AGENT | grep " --comment \"%s\"" | sed -e "s/^-A/iptables -w -t nat -D/" | sh`, id)
}

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Starting watcher")

	namespaces := make(chan event, 32)
	defer close(namespaces)
	go watch(clientset, "namespaces", &v1.Namespace{}, namespaces, 15)

	pods := make(chan event, 64)
	defer close(pods)
	go watch(clientset, "pods", &v1.Pod{}, pods, 31)

	nsIps := make(map[string]string)

	for {
		select {
		case e := <-namespaces:
			ns := e.item.(*v1.Namespace)
			if ip, ok := ns.Annotations["source-nat-agent/ip"]; ok && e.added {
				fmt.Printf(" [NS] [ADD/UPD] %s %s\n", ns.Name, ip)
				nsIps[ns.Name] = ip

				// this command has been moved here from the "on pod created/running" code,
				// assuming that this is per-node/per-namespace setup code that needs to run only once per source ip
				shell("ip addr add %s/32 dev $(ip route get 1 | head -n1 | cut -d' ' -f5)", ip)
			} else {
				// annotation not there or deleted --> ensure we don't keep the entry around

				// to produce fully correct results, if it should be valid that the annotation can be dropped from
				// a ns or changed to a different value, then we would need to process all current pods and re-setup
				// their rules

				fmt.Printf(" [NS] [DEL] %s %s\n", ns.Name, ip)
				delete(nsIps, ns.Name)
			}
		case e := <-pods:
			pod := e.item.(*v1.Pod)
			id := fmt.Sprintf("source-nat-agent:%s:%s", pod.Namespace, pod.Name)
			if e.added {
				fmt.Printf("[POD] [ADD/UPD] %s/%s phase=%s pod_ip=%s source_ip=%s\n", pod.Namespace, pod.Name, pod.Status.Phase, pod.Status.PodIP, nsIps[pod.Namespace])
				if sourceIp, ok := nsIps[pod.Namespace]; ok {
					// again, ideally here we would just keep our own in-memory state of what we know exists as iptables
					// rules and would not have to re-check the rules each time we think we may need to do something
					// the upside of that would also be that the full re-read of the pods would then not trigger
					// any shell commands for all already-known pods, so we could do it more often and cheaper,
					// which helps with reacting to any watch events we may have missed, which is not an usual thing to
					// happen, i.e. a k8s watch operation is not guaranteed to send all events all of the time
					if command(`iptables -w -t nat -S SOURCE-NAT-AGENT | grep -q " --comment \"%s\" -j SNAT --to-source %s\"`, id, sourceIp).Run() != nil {
						cleanRule(id)
						if _, err := command("iptables -w -t nat -A SOURCE-NAT-AGENT -s %s -m comment --comment %s -j SNAT --to-source %s", pod.Status.PodIP, id, sourceIp).Output(); err != nil {
							_, _ = fmt.Fprintf(os.Stderr, "iptables error: %s\n", err)
						}
					}
				}
				// ignoring case where namespace has no ip annotation set or we haven't seen that namespace yet
				// assuming that we'll have a namespace ip next time we get an event about this pod
			} else {
				fmt.Printf("[POD] [DEL] %s/%s phase=%s pod_ip=%s source_ip=%s\n", pod.Namespace, pod.Name, pod.Status.Phase, pod.Status.PodIP, nsIps[pod.Namespace])
				cleanRule(id)
			}
		}
	}
}

// -- helper types & functions --

type event struct {
	added bool
	item  interface{}
}

func watch(clientset *kubernetes.Clientset, resource string, objType runtime.Object, ch chan event, resyncSeconds time.Duration) {
	watchlist := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), resource, v1.NamespaceAll, fields.Everything())
	_, controller := cache.NewInformer(watchlist, objType, resyncSeconds*time.Second, makeHandler(ch))

	go controller.Run(nil)
}

func makeHandler(ch chan event) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(it interface{}) {
			ch <- event{true, it}
		},
		UpdateFunc: func(_, it interface{}) {
			ch <- event{true, it}
		},
		DeleteFunc: func(it interface{}) {
			ch <- event{false, it}
		},
	}
}

// set up the command, let the user decide when to run it and what to do with the result
func command(cmd string, args ...interface{}) *exec.Cmd {
	return exec.Command("sh", "-c", fmt.Sprintf(cmd, args...))
}

// run shell command and ignore its result
func shell(cmd string, args ...interface{}) {
	_ = command(cmd, args...).Run()
}
