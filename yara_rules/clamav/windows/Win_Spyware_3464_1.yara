rule Win_Spyware_3464_1
{
strings:
	$a0 = { c1b8896f9947f4cb1abadf43ba045c14d4234ed8d17a3feb9e580cd15cb432cc584c3c8a17ea9cc292b0e05c55854d5fcaa0830138793729d8b609603c65b9e09855d48873114198979e08152801a2fb14f1678627e58a58ea81c929009483ad243ddcf4eb707b073cbfa88ab9a90f8690e4fa3c36b288cedac749b1871e7e62cd121e6360f1bd8aef6f7ef75e5ce898 }

condition:
	$a0
}

        