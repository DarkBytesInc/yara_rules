rule Win_Trojan_Bancos_740
{
strings:
	$a0 = { 675242c18f025012ba1dd95bf2b3167e768f1b520449ea843583811a5074622c90cf6becefcab7886d4e20a9f66b6fe8f8caadd18584eaa52113b1d3c78abc6a8218adc40f91474d94884be71f15fb60de4e7c6edb6fda2e3b6ca1d633525b3adf5341323794adb533275d478a29207ed3e177a3 }

condition:
	$a0
}

        