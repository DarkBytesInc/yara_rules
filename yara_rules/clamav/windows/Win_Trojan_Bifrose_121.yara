rule Win_Trojan_Bifrose_121
{
strings:
	$a0 = { 1efcf2e1a8a48b5cdc36b638f69d6092eacce9e1eee189025fe55bb3e78f6056eb88e2e919a77fd78beb9d20253299ee0daac76aafd5742cbbd37f5d401a84ee1bf4c61a8cc5617fb1952d5556038aee16f89f0595d2206fbbd82f45511299bc03b6824a94d2792cb5d23e594b56ebf672b084cca0a0e8f9684aa0604d1e4ddc }

condition:
	$a0
}

        