rule Win_Trojan_Hupigon_914
{
strings:
	$a0 = { e169b5ddbdf7a0e989882de9d892cdde83cb4b59197f0f6332dd60fc35d7b700aad75fb38e0bbc0f86866a4ae4ff89f3ea8f8caef5ef717a5a7da7f4048156f74057ae6e60008f29654f22e693c8d78e114d39a8e3374f545a8cbef3258ada }

condition:
	$a0
}

        
