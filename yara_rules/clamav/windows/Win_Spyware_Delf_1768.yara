rule Win_Spyware_Delf_1768
{
strings:
	$a0 = { e281271001f5a4e3e1e6a2b0b1b9bab4d8d801c00a03c98daba5bba2c291b6b6a74c8011568392b8bdfbdfd7c772c4e0c3503b30004e38a7a2edcdd6c4c7faec99300460ac1967ea1f53cace8a25be89cef232f2314012713b111d1d80e1c2ba751cc10b23f7e26867332b032e982c3cca5d5f033a363400189007a25b }

condition:
	$a0
}

        