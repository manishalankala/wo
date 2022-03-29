

Retain: Data will not be deleted unless manually requested

Recycle: Deletes all of the data by removing it's files.
This can be useful to reuse a disk that is not dynamically provisioned, for example a NFS disk

Delete: Deletes the underlying storage (only applies on cloud storage, 
some StorageClasses won't be able to delete the underlying disk)


HostPath: The volume itself does not contain scheduling information. 
If you want to fix each pod on a node, you need to configure scheduling information, such as nodeSelector, for the pod.

LocalVolume: The volume itself contains scheduling information, 
and the pods using this volume will be fixed on a specific node, which can ensure data continuity.



#### Errors

1 pod has unbound immediate PersistentVolumeClaims.

1 node(s) had taint {node-role.kubernetes.io/master: }, that the pod didn't tolerate.
