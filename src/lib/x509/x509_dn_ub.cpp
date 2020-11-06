/*
* DN_UB maps: Upper bounds on the length of DN strings
*
* This file was automatically generated by ./src/scripts/oids.py on 2019-10-21
*
* All manual edits to this file will be lost. Edit the script
* then regenerate this source file.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>
#include <botan/asn1_obj.h>
#include <map>

namespace {

/**
 * Upper bounds for the length of distinguished name fields as given in RFC 5280, Appendix A.
 * Only OIDS recognized by botan are considered, so far.
 * Maps OID string representations instead of human readable strings in order
 * to avoid an additional lookup.
 */
static const std::map<Botan::OID, size_t> DN_UB =
   {
   { Botan::OID({2,5,4,10}), 64 }, // X520.Organization
   { Botan::OID({2,5,4,11}), 64 }, // X520.OrganizationalUnit
   { Botan::OID({2,5,4,12}), 64 }, // X520.Title
   { Botan::OID({2,5,4,3}), 64 }, // X520.CommonName
   { Botan::OID({2,5,4,4}), 40 }, // X520.Surname
   { Botan::OID({2,5,4,42}), 32768 }, // X520.GivenName
   { Botan::OID({2,5,4,43}), 32768 }, // X520.Initials
   { Botan::OID({2,5,4,44}), 32768 }, // X520.GenerationalQualifier
   { Botan::OID({2,5,4,46}), 64 }, // X520.DNQualifier
   { Botan::OID({2,5,4,5}), 64 }, // X520.SerialNumber
   { Botan::OID({2,5,4,6}), 3 }, // X520.Country
   { Botan::OID({2,5,4,65}), 128 }, // X520.Pseudonym
   { Botan::OID({2,5,4,7}), 128 }, // X520.Locality
   { Botan::OID({2,5,4,8}), 128 }, // X520.State
   { Botan::OID({2,5,4,9}), 128 } // X520.StreetAddress
   };
}

namespace Botan {

//static
size_t X509_DN::lookup_ub(const OID& oid)
   {
   auto ub_entry = DN_UB.find(oid);
   if(ub_entry != DN_UB.end())
      {
      return ub_entry->second;
      }
   else
      {
      return 0;
      }
   }
}

