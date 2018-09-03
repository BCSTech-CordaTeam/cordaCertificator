# Corda Certificator

A simple tool for generating production certificates for a Corda network.


## Use

Build a jar with `./gradlew jar`.
It'll be located in `build/libs`

You can get all the relevant help information with `java -jar <jarfile>`, replicated here as of version 0.1.

```
usage: gentool
 -nd,--node-dir <arg>     Put the nodes' certificates under this directory
 -nn,--node-names <arg>   Generate the following nodes
 -rg,--root-gen <arg>     Generate root zone certificates and store them
                          in this directory.
 -rn,--root-names <arg>   Sets the name for the root zone.
 -rr,--root-read <arg>    Use root zone certs in this directory.
```