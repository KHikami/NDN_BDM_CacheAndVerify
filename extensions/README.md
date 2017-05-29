Forwarder.cpp will break the ndnSIM if you run it from this template... so don't...

Copy paste the files into the following places:
ns-3/src/ndnSIM/apps
 + security-toy-client-app.hpp
 + security-toy-client-app.cpp
 + evil-producer.hpp
 + evil-producer.cpp

ns-3/src/ndnSIM/NFD/daemon/fw
 + forwarder.cpp
 + forwarder.hpp

place the scenario files into ns-3/src/ndnSIM/examples
