rule Win_Trojan_VB_75
{
strings:
	$a0 = { 32040078ff74ff2904006cff54ff00270b7d0000002378ff1b3c012a2374ff0450ff346c50ff0a340104003c32060078ff74ff50ff00270b370000002378ff1b3d012a2374ff0450ff346c50ff0a360104003c32060078ff74ff50ff001d0b7d0000002378ff1b3c012a2374ff1008070f0032040078ff74ff001b046cff0500002401000d1c000200086cff0d500032011a6cff0027 }

condition:
	$a0
}

        