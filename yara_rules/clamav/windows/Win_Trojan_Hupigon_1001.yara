rule Win_Trojan_Hupigon_1001
{
strings:
	$a0 = { dea73f54689206148df4181ca14c13da7e22a284073abce6f8ebcd607ed3dba95c080f751f7a67ffeb1bbaab778414d1acb298e86e3c13a036dcdca3b95973a8a71c1d714fcb30fea81d443ba02b0c4c2de7567b52c07cd3270671b2e55faafbc3c6b6f79baa0f51e5 }

condition:
	$a0
}

        
