rule Win_Trojan_Small_3662
{
strings:
	$a0 = { 11de16e3eccf2d924e1ae7ae97572661a5c650e52c2018e1fe0ffd920c79a85a623de33d11111de3bad103867097ea543adee58092eba6c3e518a384f09cb737f7ad7035cb38846a9e60443a64f627df0b95d8dbf378ecfe7195 }

condition:
	$a0
}

        
