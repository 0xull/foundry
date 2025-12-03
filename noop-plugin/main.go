package main

import (
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Check: cmdCheck,
		Del:   cmdDel,
	}, version.All, "noop-plugin v0.1.0")
}

func cmdAdd(args *skel.CmdArgs) error {
	file, err := os.OpenFile("/tmp/noop-cni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Log supplied config and env parameters
	fmt.Fprintf(file, "ADD COMMAND RECEIVED\n")
	fmt.Fprintf(file, "ContainerID: %s\n", args.ContainerID)
	fmt.Fprintf(file, "Netns: %s", args.Netns)
	fmt.Fprintf(file, "Ifname: %s", args.IfName)
	fmt.Fprintf(file, "Args: %s", args.Args)
	fmt.Fprintf(file, "Path: %s", args.Path)
	fmt.Fprintf(file, "Stdin: %s", string(args.StdinData))
	fmt.Fprintf(file, "----------------------------------------------------\n")

	// Return a dummy result in place
	result := &types100.Result{
		CNIVersion: "1.0.0",
		Interfaces: []*types100.Interface{
			{
				Name: args.IfName, 
				Mac: "02:00:00:00:00:01", 
				Sandbox: args.Netns},
		},
	}

	return types.PrintResult(result, result.CNIVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	file, err := os.OpenFile("/tmp/noop-cni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "CHECK COMMAND RECEIVED\n")
	fmt.Fprintf(file, "----------------------------------------------------\n")
	
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	file, err := os.OpenFile("/tmp/noop-cni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "DEL COMMAND RECEIVED\n")
	fmt.Fprintf(file, "ContainerID: %s", args.ContainerID)
	fmt.Fprintf(file, "----------------------------------------------------\n")
	
	return nil
}
