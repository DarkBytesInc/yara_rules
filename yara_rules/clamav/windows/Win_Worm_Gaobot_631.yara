rule Win_Worm_Gaobot_631
{
strings:
	$a0 = { cc6d2c79e26f1ecc462735e0535168705afd5be76cf15d9b6b30ac72ea779b63335b1ef67dfbfd6d9179cc7d0e5e04704c3b008dcf2a7642dc365081636979ab270aa10eb295a8fbdbfbc11503088706cc7d615a058d72e3d6b751309dbdf4aff0d84b842602595b9930cbe2669f8be5cbe059aacad3f0f591e0868c7199a2fbfa046016a0b87314b969e6c25e752687f5a4e4e4c333 }

condition:
	$a0
}

        