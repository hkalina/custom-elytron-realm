Demo: Custom security realm for WildFly Elytron
===============================================

Compile
-------

        mvn package

Add module into WildFly
-----------------------

        bin/jboss-cli.sh
        module add --name=jk.demo.myrealm --resources=myrealm-1.0-SNAPSHOT.jar --dependencies=org.wildfly.security.elytron,org.wildfly.extension.elytron

Add custom-realm into subsystem
-------------------------------

        /subsystem=elytron/custom-realm=myRealm:add(module=jk.demo.myrealm, class-name=MyRealm, configuration={myAttribute="myValue"})

