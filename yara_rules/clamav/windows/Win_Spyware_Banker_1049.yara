rule Win_Spyware_Banker_1049
{
strings:
	$a0 = { f5a47ca29aa22714f46942be9015e5365cea730b38f8d89d2460c3c930dc29b7c9d0ee7ad77293457e1cca979bfa8f633b8fd4140f73072faeb387fe5e4cf0f6c2400922c6ad7bd32767616cab797c7672cb75ee1d5061e0689c3bb207cef7507af5c14a1fa7d08c8b274a6545f7c9e46e3577ed3b09e00728271079022bd300db60b1cafd87a6e3b1cf7d147f64c41e13969a13cdaf }

condition:
	$a0
}

        