rule Win_Spyware_Lineage_11
{
strings:
	$a0 = { 5b73f669700d0a13065230740f80b1ffbfb64d41494c2046524f4d3a2013130d6adf99f533406d6963728041b26514b72e586d3e635fb624b6ff5243505420544f393cbf293887fcb26b444154412dffdffd0d106167652d49643248414b2e62 }

condition:
	$a0
}

        