rule Win_Spyware_ot_71
{
strings:
	$a0 = { cce23b69324caeed3a36c302951f602d2ee989f75eab5249cff539969ee54dd5ad9917fb2a2581d479d53db722512d76b869ca3ad8ef19b426ed0674eb22d95ca3b62ad268e95f9ee87bb5a97c3ed9c6efebccb14cf094c9fb1e1dbf19a3f17e37d93b92a3779a9bca67c651f17f647eb9b777c6fae9 }

condition:
	$a0
}

        
