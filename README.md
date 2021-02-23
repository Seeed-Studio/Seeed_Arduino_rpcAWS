# Wio Terminal AWS IoT 

![Build Status](https://github.com/jandelgado/esp32-aws-iot/workflows/run%20tests/badge.svg)

This is a fork of https://github.com/jandelgado/esp32-aws-iot which is also a fork of the original repository https://github.com/ExploreEmbedded/Hornbill-Examples. 

The original library is written for ESP32 and this is ported to work with Wio Terminal. Now you can use Wio Terminal with eRPC protocol software to connect to AWS IoT. 

## Changes by Jan Delgado
This is upgraded to AWS IoT Device SDK v3.0.1. The library was modified so that the TLS configuration (i.e. certificates and
stuff) is _no longer_ included in the library code self, but is now passed to
the `AWS_IOT` class from the client code. This makes the library easier usable.


## Original Author

Jan Delgado <jdelgado at gmx.net>, original work from https://github.com/ExploreEmbedded/Hornbill-Examples.
