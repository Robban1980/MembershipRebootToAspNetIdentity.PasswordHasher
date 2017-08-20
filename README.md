# MembershipRebootToAspNetIdentity.PasswordHasher
Example of a password hasher moving from BrockAllen.MembershipReboot to ASP.NET Core Identity

This can be used so that when you migrate from [BrockAllen.MembershipReboot](https://github.com/brockallen/BrockAllen.MembershipReboot) to ASP.NET Core Identity [ASP.NET Core Identity](https://github.com/aspnet/Identity).

On line 30 in PasswordHasher.cs you need to check that it matches your hash format in the DB. if it does not replace it with the format you use or possibly with pattern matching in case you have used multiple hashes.

To use the custom password hasher, in your UserManager's constructor your want to overwrite the base.PasswordHasher property with a new instance of this custom one. 
It takes the passwordHasher that was injected in the constructor as an argument. This is because if the password hash is not a MembershipReboot hash it will call the base passwordHasher.
```c#
base.PasswordHasher = new AgathaPasswordHasher<TUser>(passwordHasher);
```

And that should be it. Now you should be able to use the backwards compatible password hasher.