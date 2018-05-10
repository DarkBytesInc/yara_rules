/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_Hikit_msrv
{

  meta:
    author = "ThreatConnect Intelligence Research Team"
    description = "APT_Hikit_msrv"
    severity = "10"
    type = "Advanced Persistent Threat"

strings:
    $m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}

condition:
    any of them
}

