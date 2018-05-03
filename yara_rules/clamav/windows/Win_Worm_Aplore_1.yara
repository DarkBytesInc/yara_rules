rule Win_Worm_Aplore_1
{
strings:
	$a0 = { 454520504f524e3c2f613e00ae35bf0adf636e746c5fc05f1fa98dbc1570a61220a9f24309129f5c68776e6410995461ce4e }

condition:
	$a0
}

        
