rule Win_Trojan_Bifrose_729
{
strings:
	$a0 = { 32340b7652f42929b0616dee426554bc758e2e2b1fb50076a1dba32a95c044e3f6033d4b9c802a89503a5f5b6671d022c43938e0388cab72f46f28b8bf00dd0a8eddb5065faf6a835375058dc94785842b31371f64f96e3ea2b33ba449bce841b2cf7b434b2373585188dca83943248b6d0479225b1ac57ab063500903fec7583929abee1b5f972db2f542e5f969a1cf9a18225224ba7c256d69ee6e673537f72649320414cedc47be7dd7172511a062 }

condition:
	$a0
}

        