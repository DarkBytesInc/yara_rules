rule Win_Trojan_Agent_32653
{
strings:
	$a0 = { 0c7c8158869c71c8385da61517498d28ccff4327c357ac2da0c07af95a7d70a1c3360c5f373aa3b7d5eaed1b28fc052de98629214fc73926babfe678c962bb335eb2dafccdf1527f458beec5027358cbe2a1dc8081260fe699c26f1d534ae65298e643364181b775c0ac91c132286c4be5f976ce237016035b34b66cdee342153d923fbdd5725aefc90ccc46 }

condition:
	$a0
}

        