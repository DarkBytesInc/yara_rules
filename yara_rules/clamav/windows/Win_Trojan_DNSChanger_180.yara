rule Win_Trojan_DNSChanger_180
{
strings:
	$a0 = { ba9df138afa509e9acb1b42845a415e544baa3f884a5f5524da4773944789f1e55c7dfe8cf9df7e75ae5af284530d51455e59f5081bbdfe89ba476e87ab9c12845fc9ebf9ca4b51855e59f2895fc09eaaea507f559e59fe7baa19ffe54b5dfe8431a9ce85aadaf284504fe43776569ac9a308c6c31c52c2e3dfbd2de950ddfe853a5 }

condition:
	$a0
}

        