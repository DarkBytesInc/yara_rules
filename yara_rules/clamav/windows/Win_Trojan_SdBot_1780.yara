rule Win_Trojan_SdBot_1780
{
strings:
	$a0 = { dd9fe370eefb0aaecafb2a6af8e9aaf834347a437d42333a73d23bed7ea666b1eec46ff7b91181b36a96efdf48c68295bb3e8efd13c2b70feb96b460b9d314721b519bbb573ceac2ac91c89841d2fa9a34cf5c44bdc82441ef5ae487ee5cae2a59d9 }

condition:
	$a0
}

        
