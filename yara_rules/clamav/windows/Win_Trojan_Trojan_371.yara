rule Win_Trojan_Trojan_371
{
strings:
	$a0 = { 35102cf41daaf4fb3146428cf240100d260c3a7a466c6d585fc53fea033b2be78cfca6375feec89a880bf9724bffa7afda47806afa543e9673060cb5febe2a7cebefcb39037db9a5ff537cb6f4f76ba6b43abf174ae6499e4efaf16e2247ebb00759d23583e618424f33a9460a1fba }

condition:
	$a0
}

        
