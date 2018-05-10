/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule stampado_overlay
{
  meta:
    description = "Catches Stampado samples looking for at the beginning of PE overlay section"
    reference = ""
    author = "Fernando Merces, FTR, Trend Micro"
    date = "2016-07"
    md5 = "6337f0938e4a9c0ef44ab99deb0ef466"
    severity = "10"
    type = "Ransomware"

condition:
pe.characteristics == 0x122 and
pe.number_of_sections == 5 and
pe.imports("VERSION.dll", "VerQueryValueW") and uint8(pe.sections[4].raw_data_offset + pe.sections[4].raw_data_size) == 0x0d

}
