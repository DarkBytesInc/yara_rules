rule Win_Trojan_Mybot_472
{
strings:
	$a0 = { 6f2666a89f46bf7969decb963d868c445707b9aca3274c67675ea2fc727f62435df705f8264e588dc092a71b943b5a6780027b416cb066b5721cd6234303ea7066fcdf2a64713e5c14eaccb0a08558abef188d78f9c5e5df740aa1f8d3f3c645edf6d9c194981f04d5cd354e72b1789fcd141eb5ec82d6eb3f66ceee14e1fef651104c094b9470abf1fb7e }

condition:
	$a0
}

        