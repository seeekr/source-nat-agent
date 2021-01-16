package main

import (
	"context"
	"fmt"
	"k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/exec"
	"time"
)

const podsResyncSeconds = 60
const namespacesResyncSeconds = 60
const ipAnnotation = "source-nat-agent/ip"

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
}

func terminate() {
	shell("iptables -w -t nat -D POSTROUTING -j SOURCE-NAT-AGENT 2>/dev/null")
	shell("iptables -w -t nat -F SOURCE-NAT-AGENT 2>/dev/null")
	shell("iptables -w -t nat -X SOURCE-NAT-AGENT 2>/dev/null")
}

func cleanRule(id string) {
	shell(`iptables -w -t nat -S SOURCE-NAT-AGENT | grep " --comment \"%s\"" | sed -e "s/^-A/iptables -w -t nat -D/" | sh`, id)
}

func main() {
	// probably also not smart to remove all rules when we're shutting down
	// I'm assuming this is here for debugging purposes
	// should likely be removed for proper production usage
	defer terminate()

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	namespaces := make(chan event, 32)
	defer close(namespaces)
	pods := make(chan event, 64)
	defer close(pods)

	fmt.Println("Starting watchers")

	// start watching
	go watch(clientset, "namespaces", &v1.Namespace{}, namespaces, namespacesResyncSeconds, toNsInfo, func(old interface{}, new interface{}) bool {
		return true
	})
	go watch(clientset, "pods", &v1.Pod{}, pods, podsResyncSeconds, toPodInfo, func(old interface{}, new interface{}) bool {
		// we only care about updates if pod's ip has changed
		return old.(*v1.Pod).Status.PodIP != new.(*v1.Pod).Status.PodIP
	})

	nsIps := make(map[string]string)

	// list and add all namespaces before we start processing events
	if nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metaV1.ListOptions{}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "initial listing of namespaces failed: %s\n", err)
	} else {
		for _, ns := range nsList.Items {
			if ip, ok := ns.Annotations[ipAnnotation]; ok {
				fmt.Printf(" [NS] [ADD/UPD] %s %s\n", ns.Name, ip)
				nsIps[ns.Name] = ip
				shell("ip addr add %s/32 dev $(ip route get 1 | head -n1 | cut -d' ' -f5)", ip)
			}
		}
	}

	// event loop
	for {
		select {
		case e := <-namespaces:
			ns := e.item.(nsInfo)
			if e.added {
				ip := ns.NatIp
				// if the ip was set previously but not any more, we need to remove the ip mapping and cascade to pods
				if ip == "" {
					if _, ok := nsIps[ns.Name]; ok {
						fmt.Printf(" [NS] [DEL] %s\n", ns.Name)
						delete(nsIps, ns.Name)
						triggerPodEvents(clientset, &ns, pods, false)
					}
					continue
				}
				if nsIps[ns.Name] == ip {
					continue
				}
				fmt.Printf(" [NS] [ADD/UPD] %s %s\n", ns.Name, ip)
				nsIps[ns.Name] = ip

				shell("ip addr add %s/32 dev $(ip route get 1 | head -n1 | cut -d' ' -f5)", ip)
				triggerPodEvents(clientset, &ns, pods, true)
			} else {
				if _, ok := nsIps[ns.Name]; ok {
					fmt.Printf(" [NS] [DEL] %s\n", ns.Name)
					delete(nsIps, ns.Name)
				}
			}
		case e := <-pods:
			pod := e.item.(podInfo)
			id := fmt.Sprintf("source-nat-agent:%s:%s", pod.Namespace, pod.Name)
			if !e.added {
				fmt.Printf("[POD] [DEL] %s/%s phase=%s pod_ip=%s source_ip=%s\n", pod.Namespace, pod.Name, pod.Phase, pod.PodIP, nsIps[pod.Namespace])
				cleanRule(id)
				continue
			}
			sourceIp, ok := nsIps[pod.Namespace]
			if !ok {
				// ignoring case where namespace has no ip annotation set or we haven't seen that namespace yet
				// assuming that we'll have a namespace ip next time we get an event about this pod
				continue
			}
			fmt.Printf("[POD] [ADD/UPD] %s/%s phase=%s pod_ip=%s source_ip=%s\n", pod.Namespace, pod.Name, pod.Phase, pod.PodIP, nsIps[pod.Namespace])
			if command(`iptables -w -t nat -S SOURCE-NAT-AGENT | grep -q " --comment \"%s\" -j SNAT --to-source %s\"`, id, sourceIp).Run() != nil {
				cleanRule(id)
				if pod.PodIP == "" {
					// can't add an iptables rule while the pod's ip has not been set yet
					continue
				}
				if _, err := command("iptables -w -t nat -A SOURCE-NAT-AGENT -s %s -m comment --comment %s -j SNAT --to-source %s", pod.PodIP, id, sourceIp).Output(); err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "iptables error: %s\n", err)
				}
			}
		}
	}
}

func triggerPodEvents(clientset *kubernetes.Clientset, ns *nsInfo, pods chan<- event, added bool) {
	if podList, err := clientset.CoreV1().Pods(ns.Name).List(context.TODO(), metaV1.ListOptions{}); err != nil {
		msg := "listing pods failed when cascading ip changes for namespace '%s': %s"
		_, _ = fmt.Fprintf(os.Stderr, msg, ns.Name, err)
	} else {
		for _, p := range podList.Items {
			pods <- event{added, toPodInfo(&p)}
		}
	}
}

// -- helper types & functions --

type event struct {
	added bool
	item  interface{}
}

type nsInfo struct {
	Name  string
	NatIp string
}

func toNsInfo(it interface{}) interface{} {
	ns := it.(*v1.Namespace)
	return nsInfo{ns.Name, ns.Annotations[ipAnnotation]}
}

type podInfo struct {
	Namespace string
	Name      string
	Phase     string
	PodIP     string
}

func toPodInfo(it interface{}) interface{} {
	pod := it.(*v1.Pod)
	return podInfo{pod.Namespace, pod.Name, string(pod.Status.Phase), pod.Status.PodIP}
}

func watch(clientset *kubernetes.Clientset, resource string, objType runtime.Object, ch chan event, resyncSeconds time.Duration, toInfo func(it interface{}) interface{}, updateFilter func(old interface{}, new interface{}) bool) {
	watchlist := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), resource, v1.NamespaceAll, fields.Everything())
	_, controller := cache.NewInformer(watchlist, objType, resyncSeconds*time.Second, makeHandler(ch, toInfo, updateFilter))

	go controller.Run(nil)
}

func makeHandler(ch chan event, toInfo func(it interface{}) interface{}, updateFilter func(old interface{}, new interface{}) bool) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(it interface{}) {
			ch <- event{true, toInfo(it)}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			if updateFilter(old, new) {
				ch <- event{true, toInfo(new)}
			}
		},
		DeleteFunc: func(it interface{}) {
			if d, ok := it.(cache.DeletedFinalStateUnknown); ok {
				ch <- event{false, toInfo(d.Obj)}
			} else {
				ch <- event{false, toInfo(it)}
			}
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
