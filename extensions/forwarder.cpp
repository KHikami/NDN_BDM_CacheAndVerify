/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2016,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "forwarder.hpp"
#include "algorithm.hpp"
#include "core/logger.hpp"
#include "strategy.hpp"
#include "table/cleanup.hpp"
#include <ndn-cxx/lp/tags.hpp>
#include "face/null-face.hpp"
#include <boost/random/uniform_int_distribution.hpp>
#include <vector>
#include <string>
#include <memory>

//#include <iostream>

using namespace std;

namespace nfd {

NFD_LOG_INIT("Forwarder");

Forwarder::Forwarder()
  : m_unsolicitedDataPolicy(new fw::DefaultUnsolicitedDataPolicy())
  , m_fib(m_nameTree)
  , m_pit(m_nameTree)
  , m_measurements(m_nameTree)
  , m_strategyChoice(m_nameTree, fw::makeDefaultStrategy(*this))
  , m_csFace(face::makeNullFace(FaceUri("contentstore://")))
{
  fw::installStrategies(*this);
  getFaceTable().addReserved(m_csFace, face::FACEID_CONTENT_STORE);

  m_faceTable.afterAdd.connect([this] (Face& face) {
    face.afterReceiveInterest.connect(
      [this, &face] (const Interest& interest) {
        this->startProcessInterest(face, interest);
      });
    face.afterReceiveData.connect(
      [this, &face] (const Data& data) {
        this->startProcessData(face, data);
      });
    face.afterReceiveNack.connect(
      [this, &face] (const lp::Nack& nack) {
        this->startProcessNack(face, nack);
      });
  });

  m_faceTable.beforeRemove.connect([this] (Face& face) {
    cleanupOnFaceRemoval(m_nameTree, m_fib, m_pit, face);
  });
}

Forwarder::~Forwarder() = default;

void
Forwarder::startProcessInterest(Face& face, const Interest& interest)
{
  // check fields used by forwarding are well-formed
  try {
    if (interest.hasLink()) {
      interest.getLink();
    }
  }
  catch (const tlv::Error&) {
    NFD_LOG_DEBUG("startProcessInterest face=" << face.getId() <<
                  " interest=" << interest.getName() << " malformed");
    // It's safe to call interest.getName() because Name has been fully parsed
    return;
  }

  this->onIncomingInterest(face, interest);
}

void
Forwarder::startProcessData(Face& face, const Data& data)
{
  // check fields used by forwarding are well-formed
  // (none needed)

  this->onIncomingData(face, data);
}

void
Forwarder::startProcessNack(Face& face, const lp::Nack& nack)
{
  // check fields used by forwarding are well-formed
  try {
    if (nack.getInterest().hasLink()) {
      nack.getInterest().getLink();
    }
  }
  catch (const tlv::Error&) {
    NFD_LOG_DEBUG("startProcessNack face=" << face.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " malformed");
    return;
  }

  this->onIncomingNack(face, nack);
}

void
Forwarder::onIncomingInterest(Face& inFace, const Interest& interest)
{
  // receive Interest
  NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                " interest=" << interest.getName());
  interest.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInInterests;

  //cout << "Receieved an Interest on face" << inFace.getId() << " interest=" << interest.getName() << endl;
  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(interest.getName());
  //cout << "made it past violating host check " << endl;
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingInterest face=" << inFace.getId() <<
                  " interest=" << interest.getName() << " violates /localhost");
    //cout << "onIncomingInterest face=" << inFace.getId() <<
      //            " interest=" << interest.getName() << " violates /localhost" << endl;
    // (drop)
    return;
  }

  // detect duplicate Nonce with Dead Nonce List
  //cout << "interest name " << interest.getName() << ", interest nonce " << interest.getNonce() <<endl;
  //cout << "Dead Nonce List Size" << m_deadNonceList.size() << endl;
  bool hasDuplicateNonceInDnl = m_deadNonceList.has(interest.getName(), interest.getNonce());
  //cout << "Duplicate nonce exists" << hasDuplicateNonceInDnl << endl;
  if (hasDuplicateNonceInDnl) {
    // goto Interest loop pipeline
    //cout << "Duplicate Nonce!" << endl;
    this->onInterestLoop(inFace, interest);
    return;
  }

  // PIT insert
  //cout << "Pit " << m_pit.size() << endl;
  shared_ptr<pit::Entry> pitEntry = m_pit.insert(interest).first;
  //cout << "pitEntry" << pitEntry << endl;
  // detect duplicate Nonce in PIT entry
  bool hasDuplicateNonceInPit = fw::findDuplicateNonce(*pitEntry, interest.getNonce(), inFace) !=
                                fw::DUPLICATE_NONCE_NONE;
  if (hasDuplicateNonceInPit) {
    // goto Interest loop pipeline
    this->onInterestLoop(inFace, interest);
    return;
  }

  // cancel unsatisfy & straggler timer
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

  //cout << "made it to trying to look in the PIT!!!" << endl;
  const pit::InRecordCollection& inRecords = pitEntry->getInRecords();
  bool isPending = inRecords.begin() != inRecords.end();
  if (!isPending) {
    if (m_csFromNdnSim == nullptr) {
      m_cs.find(interest,
                bind(&Forwarder::onContentStoreHit, this, ref(inFace), pitEntry, _1, _2),
                bind(&Forwarder::onContentStoreMiss, this, ref(inFace), pitEntry, _1));
    }
    else {
      shared_ptr<Data> match = m_csFromNdnSim->Lookup(interest.shared_from_this());
      if (match != nullptr) {
        this->onContentStoreHit(inFace, pitEntry, interest, *match);
      }
      else {
        this->onContentStoreMiss(inFace, pitEntry, interest);
      }
    }
  }
  else {
    this->onContentStoreMiss(inFace, pitEntry, interest);
  }
}

void
Forwarder::onInterestLoop(Face& inFace, const Interest& interest)
{
  // if multi-access face, drop
  if (inFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                  " interest=" << interest.getName() <<
                  " drop");
    return;
  }

  NFD_LOG_DEBUG("onInterestLoop face=" << inFace.getId() <<
                " interest=" << interest.getName() <<
                " send-Nack-duplicate");

  // send Nack with reason=DUPLICATE
  // note: Don't enter outgoing Nack pipeline because it needs an in-record.
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::DUPLICATE);
  inFace.sendNack(nack);
}

void
Forwarder::onContentStoreMiss(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                              const Interest& interest)
{
  NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName());

  // insert in-record
  pitEntry->insertOrUpdateInRecord(const_cast<Face&>(inFace), interest);

  // set PIT unsatisfy timer
  this->setUnsatisfyTimer(pitEntry);

  // has NextHopFaceId?
  shared_ptr<lp::NextHopFaceIdTag> nextHopTag = interest.getTag<lp::NextHopFaceIdTag>();
  if (nextHopTag != nullptr) {
    // chosen NextHop face exists?
    Face* nextHopFace = m_faceTable.get(*nextHopTag);
    if (nextHopFace != nullptr) {
      NFD_LOG_DEBUG("onContentStoreMiss interest=" << interest.getName() << " nexthop-faceid=" << nextHopFace->getId());
      // go to outgoing Interest pipeline
      // scope control is unnecessary, because privileged app explicitly wants to forward
      this->onOutgoingInterest(pitEntry, *nextHopFace, interest);
    }
    return;
  }

  // dispatch to strategy: after incoming Interest
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveInterest(inFace, interest, pitEntry); });
}

void
Forwarder::onContentStoreHit(const Face& inFace, const shared_ptr<pit::Entry>& pitEntry,
                             const Interest& interest, const Data& data)
{
  NFD_LOG_DEBUG("onContentStoreHit interest=" << interest.getName());

  beforeSatisfyInterest(*pitEntry, *m_csFace, data);
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, *m_csFace, data); });

  data.setTag(make_shared<lp::IncomingFaceIdTag>(face::FACEID_CONTENT_STORE));
  // XXX should we lookup PIT for other Interests that also match csMatch?

  // set PIT straggler timer
  this->setStragglerTimer(pitEntry, true, data.getFreshnessPeriod());

  // goto outgoing Data pipeline
  this->onOutgoingData(data, *const_pointer_cast<Face>(inFace.shared_from_this()));
}

void
Forwarder::onOutgoingInterest(const shared_ptr<pit::Entry>& pitEntry, Face& outFace, const Interest& interest)
{
  NFD_LOG_DEBUG("onOutgoingInterest face=" << outFace.getId() <<
                " interest=" << pitEntry->getName());

  // insert out-record
  pitEntry->insertOrUpdateOutRecord(outFace, interest);

  // send Interest
  outFace.sendInterest(interest);
  ++m_counters.nOutInterests;
}

void
Forwarder::onInterestReject(const shared_ptr<pit::Entry>& pitEntry)
{
  if (fw::hasPendingOutRecords(*pitEntry)) {
    NFD_LOG_ERROR("onInterestReject interest=" << pitEntry->getName() <<
                  " cannot reject forwarded Interest");
    return;
  }
  NFD_LOG_DEBUG("onInterestReject interest=" << pitEntry->getName());

  // cancel unsatisfy & straggler timer
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

  // set PIT straggler timer
  this->setStragglerTimer(pitEntry, false);
}

void
Forwarder::onInterestUnsatisfied(const shared_ptr<pit::Entry>& pitEntry)
{
  NFD_LOG_DEBUG("onInterestUnsatisfied interest=" << pitEntry->getName());

  // invoke PIT unsatisfied callback
  beforeExpirePendingInterest(*pitEntry);
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.beforeExpirePendingInterest(pitEntry); });

  // goto Interest Finalize pipeline
  this->onInterestFinalize(pitEntry, false);
}

void
Forwarder::onInterestFinalize(const shared_ptr<pit::Entry>& pitEntry, bool isSatisfied,
                              time::milliseconds dataFreshnessPeriod)
{
  NFD_LOG_DEBUG("onInterestFinalize interest=" << pitEntry->getName() <<
                (isSatisfied ? " satisfied" : " unsatisfied"));

  // Dead Nonce List insert if necessary
  this->insertDeadNonceList(*pitEntry, isSatisfied, dataFreshnessPeriod, 0);

  // PIT delete
  this->cancelUnsatisfyAndStragglerTimer(*pitEntry);
  m_pit.erase(pitEntry.get());
}

void
Forwarder::onIncomingData(Face& inFace, const Data& data)
{
  //Data from App is on Face ID #258... though will need to check this theory...
  // receive Data
  NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() << " data=" << data.getName());
  //cout << "onIncomingData face=" << inFace.getId() << " data=" << data.getName() << endl;
  data.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInData;

  // /localhost scope control
  bool isViolatingLocalhost = inFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onIncomingData face=" << inFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  bool fromApplicationData = (inFace.getId() == 258);

  bool isSetupData = true;

  bool appData = false;
  if(data.getName().size() >= 2)
  {
    //cout << "Data Prefix is: " << data.getName().getPrefix(2) << endl;
    appData = data.getName().getPrefix(2).isPrefixOf(Name("/prefix/data"));//the data/evil data isn't getting caught
  }
  bool keyData = data.getName().isPrefixOf(Name("/prefix/key"));

  //if appData or KeyData and is not from my application
  if((appData || keyData) && !fromApplicationData)
  {
     //cout << "Is Application Data!" << data.getName() << endl;
     isSetupData = false;
  }

  std::vector<shared_ptr<const Data>> goodData;
  std::vector<FaceId> goodFaces;

  if(!isSetupData)
  {
     //create key interest for later look up in cache if needed (since can't locate original interest from name...)
     shared_ptr<Interest> keyInterest = make_shared<Interest>();
     keyInterest->setName(Name(m_keyPrefix));
     //cout << "created empty keyInterest" << endl;
     keyInterest->setNonce(m_keyNonce);
     //cout << "Nonce is: " << m_keyNonce << endl;

     if(m_keyNonce > (std::numeric_limits<uint32_t>::max() - 1))
     {
           m_keyNonce = 255;
     }
     else
     {
        m_keyNonce++;
     }

     //should be 2000 milliseconds. (2 seconds)
     time::milliseconds interestLifeTime(2000);
     keyInterest->setInterestLifetime(interestLifeTime);

     //cout << "key interest made but not sent" << keyInterest->toUri() << endl;

     //cout << "Data Name is:" << data.getName() << endl;
     if(!keyData)
     {

        //cout << "received non-key data: " << data.getName() << endl;
        //data is not a key => find if key exists in cache. In ideal scenario, I would check data for it's key locator
        //see if key locator in cache but this is a simulation and for the sake of time...
        bool keyHit = true;
        if(m_csFromNdnSim==nullptr)
        {
          //cout << "No Content Store so going to default false!" << endl;
          keyHit = false;
         }
        else
        {
           shared_ptr<Data> keyMatch = m_csFromNdnSim->Lookup(keyInterest);
           //cout << "found cached key match: " << keyMatch << endl;
           if(keyMatch == nullptr)
           {
              keyHit=false;
              //cout << "key is null!" << endl;
           }
         }

         if(keyHit)
         {
            //cout << "auto-verifying the data" << endl;
            //I have the cached key! do data check.
            if(data.getContent().size() >= m_goodPayloadSize)
            {
               //Data and Interest are extended of Shared From This Class => method outputs a shared ptr
                goodData.push_back(data.shared_from_this());
                goodFaces.push_back(inFace.getId());
            }
          }
          else
          {
             //cout << "adding the data to push back"<< endl;
             m_dataToBeVerified.push_back(data.shared_from_this());
             m_dataToBeVerifiedInFaces.push_back(inFace.getId());

             //cout << "Created key interest: " << keyInterest->toUri() << endl;
             //process key interest :)

             this->startProcessInterest(inFace, *keyInterest);
              //cout << "Finished processing key interest!" << endl;
             m_keyOriginatedFromHere = true;
             //get out of method once key interest sent.
           return;
          }
      }//end of if !keyData
     else
     {
       //cout << "Key data received! Verifying data on stack" << endl;
       for(size_t i = 0; i < m_dataToBeVerified.size(); i++)
       {
         //in reality this should be a signature check but :P hacky way of checking payload size first...
         bool dataIsGood = m_dataToBeVerified[i]->getContent().size() >= m_goodPayloadSize;

         //cout << m_dataToBeVerified[i]->getName() << " is good? " << dataIsGood << endl;
         if(dataIsGood)
         {
            goodData.push_back(m_dataToBeVerified[i]);
            goodFaces.push_back(m_dataToBeVerifiedInFaces[i]);
         }
      }

      m_dataToBeVerified.clear();//empty out the data to be verified queue
      m_dataToBeVerifiedInFaces.clear();

      goodData.push_back(data.shared_from_this()); //have to add the key to the cache too!
      goodFaces.push_back(inFace.getId());
    }
  }
  else
  {
      //push setup data onto the good data stack ^^"
      goodData.push_back(data.shared_from_this());
      goodFaces.push_back(inFace.getId());
  }

   //for each goodData entry, do processing for the pit entries

    for(size_t j = 0; j < goodData.size(); j++)
    {
      const Data& data = *goodData[j]; //retrieve data as good data.j & do original processing per data
      //wish there was a better way to do this...
      Face& inFace = *(m_faceTable.get(goodFaces[j]));

      //cout << "Data is " << data.getName() << " from Face " << inFace.getId() << endl;
      bool isKeyData = data.getName().isPrefixOf(Name("/prefix/key"));
      //cout << "data is key data? " << isKeyData << endl;
     // PIT match
     pit::DataMatchResult pitMatches = m_pit.findAllDataMatches(data);
     if (pitMatches.begin() == pitMatches.end()) {
        // goto Data unsolicited pipeline
        this->onDataUnsolicited(inFace, data);
      }
     else{

        shared_ptr<Data> dataCopyWithoutTag = make_shared<Data>(data);
        dataCopyWithoutTag->removeTag<lp::HopCountTag>();

        //cout << "data wanted!" << data.getName() <<endl;

        // CS insert
        if (m_csFromNdnSim == nullptr)
        {
           m_cs.insert(*dataCopyWithoutTag);
        }
        else
        {
           //cout << "data added to content store!" << data.getName() << endl;
           m_csFromNdnSim->Add(dataCopyWithoutTag);
        }

        //for some reason it is not sending out the data once it's been all verified to be good...
        //I wonder if it's because the inface for the data is not correct in terms of the data?

        //note: need to modify scenarios to have the content store... (apparently it wasn't doing caching w/o it...)
        std::set<Face*> pendingDownstreams;
        // foreach PitEntry
        auto now = time::steady_clock::now();
        for (const shared_ptr<pit::Entry>& pitEntry : pitMatches) {
            NFD_LOG_DEBUG("onIncomingData matching=" << pitEntry->getName());
            //cout << "onIncomingData matching=" << pitEntry->getName() << endl;

            // cancel unsatisfy & straggler timer
            this->cancelUnsatisfyAndStragglerTimer(*pitEntry);

            // remember pending downstreams
            for (const pit::InRecord& inRecord : pitEntry->getInRecords()) {
                if (inRecord.getExpiry() > now) {
                    if(appData)
                    {
                       //cout << "data still valid" << endl;
                    }
                    pendingDownstreams.insert(&inRecord.getFace());
                 }
             }

            // invoke PIT satisfy callback
            beforeSatisfyInterest(*pitEntry, inFace, data);
            this->dispatchToStrategy(*pitEntry,
            [&] (fw::Strategy& strategy) { strategy.beforeSatisfyInterest(pitEntry, inFace, data); });

            // Dead Nonce List insert if necessary (for out-record of inFace)
            this->insertDeadNonceList(*pitEntry, true, data.getFreshnessPeriod(), &inFace);

            // mark PIT satisfied
            pitEntry->clearInRecords();
            pitEntry->deleteOutRecord(inFace);

            // set PIT straggler timer
            this->setStragglerTimer(pitEntry, true, data.getFreshnessPeriod());
        }
        // foreach pending downstream
        for (Face* pendingDownstream : pendingDownstreams) {
            //faking the loopback => if anyone requests the key, I send it back regardless
            if(!isKeyData)
            {
               if (pendingDownstream == &inFace) {
                   //cout << "not sending it down stream" << endl;
                   continue;
                  }
               // goto outgoing Data pipeline
               this->onOutgoingData(data, *pendingDownstream);
           }
           else
           {
              this->onOutgoingData(data, *pendingDownstream);
              //cout<< "is key that I got so sending it downstream" << endl;
           }
        }
     }//else end bracket for if no matches in pit
  }//good data for loop end bracket
}//on incoming data end bracket

void
Forwarder::onDataUnsolicited(Face& inFace, const Data& data)
{
  // accept to cache?
  fw::UnsolicitedDataDecision decision = m_unsolicitedDataPolicy->decide(inFace, data);
  if (decision == fw::UnsolicitedDataDecision::CACHE) {
    // CS insert
    if (m_csFromNdnSim == nullptr)
      m_cs.insert(data, true);
    else
      m_csFromNdnSim->Add(data.shared_from_this());
  }

  NFD_LOG_DEBUG("onDataUnsolicited face=" << inFace.getId() <<
                " data=" << data.getName() <<
                " decision=" << decision);
}

void
Forwarder::onOutgoingData(const Data& data, Face& outFace)
{
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingData face=invalid data=" << data.getName());
    return;
  }
  NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() << " data=" << data.getName());

  // /localhost scope control
  bool isViolatingLocalhost = outFace.getScope() == ndn::nfd::FACE_SCOPE_NON_LOCAL &&
                              scope_prefix::LOCALHOST.isPrefixOf(data.getName());
  if (isViolatingLocalhost) {
    NFD_LOG_DEBUG("onOutgoingData face=" << outFace.getId() <<
                  " data=" << data.getName() << " violates /localhost");
    // (drop)
    return;
  }

  // send Data
  outFace.sendData(data);
  ++m_counters.nOutData;
}

void
Forwarder::onIncomingNack(Face& inFace, const lp::Nack& nack)
{
  // receive Nack
  nack.setTag(make_shared<lp::IncomingFaceIdTag>(inFace.getId()));
  ++m_counters.nInNacks;

  // if multi-access face, drop
  if (inFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  // PIT match
  shared_ptr<pit::Entry> pitEntry = m_pit.find(nack.getInterest());
  // if no PIT entry found, drop
  if (pitEntry == nullptr) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-PIT-entry");
    return;
  }

  // has out-record?
  pit::OutRecordCollection::iterator outRecord = pitEntry->getOutRecord(inFace);
  // if no out-record found, drop
  if (outRecord == pitEntry->out_end()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " no-out-record");
    return;
  }

  // if out-record has different Nonce, drop
  if (nack.getInterest().getNonce() != outRecord->getLastNonce()) {
    NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                  " nack=" << nack.getInterest().getName() <<
                  "~" << nack.getReason() << " wrong-Nonce " <<
                  nack.getInterest().getNonce() << "!=" << outRecord->getLastNonce());
    return;
  }

  NFD_LOG_DEBUG("onIncomingNack face=" << inFace.getId() <<
                " nack=" << nack.getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // record Nack on out-record
  outRecord->setIncomingNack(nack);

  // trigger strategy: after receive NACK
  this->dispatchToStrategy(*pitEntry,
    [&] (fw::Strategy& strategy) { strategy.afterReceiveNack(inFace, nack, pitEntry); });
}

void
Forwarder::onOutgoingNack(const shared_ptr<pit::Entry>& pitEntry, const Face& outFace,
                          const lp::NackHeader& nack)
{
  if (outFace.getId() == face::INVALID_FACEID) {
    NFD_LOG_WARN("onOutgoingNack face=invalid" <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // has in-record?
  pit::InRecordCollection::iterator inRecord = pitEntry->getInRecord(outFace);

  // if no in-record found, drop
  if (inRecord == pitEntry->in_end()) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " no-in-record");
    return;
  }

  // if multi-access face, drop
  if (outFace.getLinkType() == ndn::nfd::LINK_TYPE_MULTI_ACCESS) {
    NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                  " nack=" << pitEntry->getInterest().getName() <<
                  "~" << nack.getReason() << " face-is-multi-access");
    return;
  }

  NFD_LOG_DEBUG("onOutgoingNack face=" << outFace.getId() <<
                " nack=" << pitEntry->getInterest().getName() <<
                "~" << nack.getReason() << " OK");

  // create Nack packet with the Interest from in-record
  lp::Nack nackPkt(inRecord->getInterest());
  nackPkt.setHeader(nack);

  // erase in-record
  pitEntry->deleteInRecord(outFace);

  // send Nack on face
  const_cast<Face&>(outFace).sendNack(nackPkt);
  ++m_counters.nOutNacks;
}

static inline bool
compare_InRecord_expiry(const pit::InRecord& a, const pit::InRecord& b)
{
  return a.getExpiry() < b.getExpiry();
}

void
Forwarder::setUnsatisfyTimer(const shared_ptr<pit::Entry>& pitEntry)
{
  pit::InRecordCollection::iterator lastExpiring =
    std::max_element(pitEntry->in_begin(), pitEntry->in_end(), &compare_InRecord_expiry);

  time::steady_clock::TimePoint lastExpiry = lastExpiring->getExpiry();
  time::nanoseconds lastExpiryFromNow = lastExpiry - time::steady_clock::now();
  if (lastExpiryFromNow <= time::seconds::zero()) {
    // TODO all in-records are already expired; will this happen?
  }

  scheduler::cancel(pitEntry->m_unsatisfyTimer);
  pitEntry->m_unsatisfyTimer = scheduler::schedule(lastExpiryFromNow,
    bind(&Forwarder::onInterestUnsatisfied, this, pitEntry));
}

void
Forwarder::setStragglerTimer(const shared_ptr<pit::Entry>& pitEntry, bool isSatisfied,
                             time::milliseconds dataFreshnessPeriod)
{
  time::nanoseconds stragglerTime = time::milliseconds(100);

  scheduler::cancel(pitEntry->m_stragglerTimer);
  pitEntry->m_stragglerTimer = scheduler::schedule(stragglerTime,
    bind(&Forwarder::onInterestFinalize, this, pitEntry, isSatisfied, dataFreshnessPeriod));
}

void
Forwarder::cancelUnsatisfyAndStragglerTimer(pit::Entry& pitEntry)
{
  scheduler::cancel(pitEntry.m_unsatisfyTimer);
  scheduler::cancel(pitEntry.m_stragglerTimer);
}

static inline void
insertNonceToDnl(DeadNonceList& dnl, const pit::Entry& pitEntry,
                 const pit::OutRecord& outRecord)
{
  dnl.add(pitEntry.getName(), outRecord.getLastNonce());
}

void
Forwarder::insertDeadNonceList(pit::Entry& pitEntry, bool isSatisfied,
                               time::milliseconds dataFreshnessPeriod, Face* upstream)
{
  // need Dead Nonce List insert?
  bool needDnl = false;
  if (isSatisfied) {
    bool hasFreshnessPeriod = dataFreshnessPeriod >= time::milliseconds::zero();
    // Data never becomes stale if it doesn't have FreshnessPeriod field
    needDnl = static_cast<bool>(pitEntry.getInterest().getMustBeFresh()) &&
              (hasFreshnessPeriod && dataFreshnessPeriod < m_deadNonceList.getLifetime());
  }
  else {
    needDnl = true;
  }

  if (!needDnl) {
    return;
  }

  // Dead Nonce List insert
  if (upstream == 0) {
    // insert all outgoing Nonces
    const pit::OutRecordCollection& outRecords = pitEntry.getOutRecords();
    std::for_each(outRecords.begin(), outRecords.end(),
                  bind(&insertNonceToDnl, ref(m_deadNonceList), cref(pitEntry), _1));
  }
  else {
    // insert outgoing Nonce of a specific face
    pit::OutRecordCollection::iterator outRecord = pitEntry.getOutRecord(*upstream);
    if (outRecord != pitEntry.getOutRecords().end()) {
      m_deadNonceList.add(pitEntry.getName(), outRecord->getLastNonce());
    }
  }
}

} // namespace nfd
