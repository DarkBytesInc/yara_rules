rule Win_Trojan_Bawasu_1
{
strings:
	$a0 = { 4df4bacc9245008b45f8e8a1dfffffb101badc9245008b45f8e86edeffffb901000000ba209345008b45f8e8acdfffffb901000000ba389345008b45f8e89adfffff8b45f8e8aeddffffb101ba589345008b45f8e833deffffb901000000baa09345008b45f8e871dfffff }

condition:
	$a0
}

        
