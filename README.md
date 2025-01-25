# Kubernetes Dashboard in a Box

> Project Status: Early Proof of Concept

This is a single-binary version of the [Kubernetes Dashboard](https://github.com/kubernetes/dashboard/) designed for temporary local execution.

## Develop

#### Create KinD Cluster

```bash
kind create cluster

kubectl create serviceaccount dashboard -n default
kubectl create clusterrolebinding dashboard-admin --clusterrole=cluster-admin --serviceaccount=default:dashboard
kubectl -n default create token dashboard
```