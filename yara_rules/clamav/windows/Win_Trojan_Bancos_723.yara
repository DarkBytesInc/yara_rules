rule Win_Trojan_Bancos_723
{
strings:
	$a0 = { 90eb17736545db438db130e8f6109b01fb7570eacd0be6eb6ffc7bd5d6fc101900113c5d9332f91e2626ba7bebe2fbd1891b6d0af0b7ea8e96fc92541be7777dca60b8b6efa93d22933c9bea05e5472f87bfbb4d739a6bca198d6f04a5ae89d7d54096369877ef115e0d4d12 }

condition:
	$a0
}

        
