# XML EXTERNAL ENTITIES

```xml
<?xml version="1.0"encoding="UTF-8"?>
<!DOCTYPE contato ..
	<!ENTITY meunome TEXT "Guilherme"> # External entity
<contato>
	<nome>&meunome;</nome>
	<telefone tipo="residencial">3199554565</telefone>
	<telefone tipo="comercial">8156754565</telefone>
</contato>
```

### External entity exploring

```xml
<!ENTITY meunome SYSTEM "file://etc/passwd">
<!ENTITY meunome SYSTEM "https://192.168.1.1/private">
<!ENTITY meunome SYSTEM "file:///dev/random">
```

- The name entity will be the file with the system passwords
- Access server local files LFI
- Get network informations
- Denial of Service (DOS) with number generator

### How Prevent

- Use less complex data formats such as JSON
- Update all XML processors and libraries
- Not serialize sensitive data
- Disable XML external entity / DTD processing
- Use XSD to validate XML / XSL files
