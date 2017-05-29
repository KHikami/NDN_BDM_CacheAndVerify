#NDN Verifying & Caching Scenarios

Same as the NDN Original BDM Scenarios but with a modified forwarder. Link to NDN Original Scenarios: https://github.com/KHikami/NDN-Original-Cache-Poisoning-Scenarios 
This is unable to run as is... you'll need to replace the files into ndnSIM to work ^^"

Note: Cloned from original NDN template scenario (https://github.com/named-data-ndnSIM/scenario-template.git) for NDN SIM on May 29th, 2017

Forwarder Logic Changes
=======================
Modified Processing InComingData() for Forwarder to do the following:
  + If data is not setup data (or doesn't match /prefix/data or /prefix/key) => ignore new logic
  + If is /prefix/data (not /prefix/key) => check if I have key cached.
     ~ if key is cached, automatically "verify" data (pretends the key verifies the data though really I'm doing a payload 
       check)
     ~ if key is not cached, create key interest and note that the key interest came from this node. Add the data & respective
       in face to the stack of data to be verified.
  + if is /prefix/key, verify the data on the stack of data to be verified
  + per verified data (declared good), do the original data processing (except for the key data, if I created an interest and 
    sent out the interest for the key => I spam all interfaces that request it from me...obviously not what I wanted but it 
    works)

Scenarios (Same as NDN Original)
=========
Scenario: Simple Signer Example
-------------------------------

Key Points: Creating multiple Producers in a network, "Verification" of data

Creates a simple layout where you have a key producer, a producer, and a consumer lined up such that the last node connects to both the key producer and producer. The consumer requests for data from the producer and will then request the key from the key producer. Currently Security Toy Client App (the consumer for the scenario) is "hardcoded" to request for the key prefix once data from the producer comes in.

Scenario: Grid Signer Example 
------------------------------

Key Points: Creating multiple Producers in a Grid Network, "Verification" of data

Creates a grid where in one corner is the consumer, in another corner the producer, and in another, the key producer. Follows the same example as the simple signer just that this one is in a grid layout.

Scenario: Basic Cache Poisoning Scenario
-----------------------------------------

Key Points: Exclude filter, Custom Evil Producer

Introduces the Evil Producer into the network. This network is a linear network where the last neutral node is connected to the producer, the 2nd to last neutral node is connected to the key producer, and the node closest to the consumer is connected to the Evil Producer (who currently generates DATA packets with "/evil" appended at the end of the name). The consumer checks the data content size (since can't really simulate easily actual payload) and ends up in pursuit mode for the correct data. While in pursuit mode, the consumer will send out an interest with Exclude set. Currently Exclude only works for the name => why it's an added suffix to the name for the DATA packets Evil Producer creates

Scenario: Crowded Cache Poisoning Scenario
------------------------------------------

Key Points: Exclude filter, Custom Evil Producer, Multiple Consumers, Delay Start

Builds on top of the Basic Cache Poisoning Scenario by adding 2 more consumers into the network such that all 3 consumers are at the same spot. However, the added twist to this is that each consumer starts with a different delay start. This is to see the effects of cache poisoning on the other 2 consumers who will request the same packets as the third. (It's pretty bad if you take a look into the results log...)

Scenario: Distributed Cache Poisoning Scenario
----------------------------------------------

Key Points: Exclude filter, Custom Evil Producer, Multiple Consumers in a Grid, Delay Start

Takes the Crowded Cache Poisoning Scenario and puts it into a grid. Consumers are on the left side of the grid and the producers are on the right. Looks into how NDN reacts in such a situation where the consumers are not from the same starting point but have various hop distances and delays from evil, good, and signer producers.

