rule Win_Trojan_Philis_80
{
strings:
	$a0 = { 7fa8bffaf72dc955dd676a083f7137159b52eb4dc2a730d107510ea3b29662fc7e02e9906377f3c350ee1cd778b2cd5c7dbc5ba4768a3705f25219f706f0c2b462d5c716cd8fd6f3bb51f75bbebb90804f8c7d1c7fe9bc7af215412d3735eb6bece45dea6517dc67333e67bd57ba9ea4b17b2fc91f85775f76e76b234bfab7f42081b2b63a3d62a6d1d2f2fa3dad933fc8521472614b }

condition:
	$a0
}

        