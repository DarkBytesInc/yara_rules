rule Win_Trojan_Bancos_717
{
strings:
	$a0 = { a5cd7db76ab5734cef21ab7946bba233e79b1ac5d9eec944797eff1ad216d640f97279e2240625b1c447be8e890cb263a2268a0fc1c6b79dcaee827b8be8f82e6ae667c06940651f0b2e12d47f999fb6e27e1beb5d52a9dceae455a27cf72b0289aea1194f75d24edf06b363 }

condition:
	$a0
}

        
