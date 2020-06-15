# Sharky CTF 2020


## Writeup


### XXExternalXX
`web` `shkCTF{G3T_XX3D_f5ba4f9f9c9e0f41dd9df266b391447a}`

[poc](./XXExternalXX/exp.xml)

> One of your customer all proud of his new platform asked you to audit it. To show him that you can get information on his server, he hid a file "flag.txt" at the server's root.
> 
> xxexternalxx.sharkyctf.xyz
> 
> Creator : Remsio

It seems that the `Show stored data` page will render a xml file
    which set with GET parameter.
The link is http://xxexternalxx.sharkyctf.xyz/?xml=data.xml

We first try to see whether it can access file with `http` and the answer is yes.
The next step is to generate a xml file and get the flag.

We first download the `data.xml` to check the format.

```xml
<root>
    <data>17/09/2019 the platform is now online, the fonctionnalities it contains will be audited by one of our society partenairs</data>
</root>
```

It is obvious that we have to put our content in `<data>` tags.
Then it's a simple XXE.

