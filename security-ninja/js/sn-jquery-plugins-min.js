/*!
 * jQuery Cookie Plugin v1.3.1
 * https://github.com/carhartl/jquery-cookie
 *
 * Copyright 2013 Klaus Hartl
 * Released under the MIT license
 */
!function(e){"function"==typeof define&&define.amd?define(["jquery"],e):e(jQuery)}((function($){var e=/\+/g;function n(e){return e}function o(n){return decodeURIComponent(n.replace(e," "))}function i(e){0===e.indexOf('"')&&(e=e.slice(1,-1).replace(/\\"/g,'"').replace(/\\\\/g,"\\"));try{return r.json?JSON.parse(e):e}catch(e){}}var r=$.cookie=function(e,t,a){if(void 0!==t){if("number"==typeof(a=$.extend({},r.defaults,a)).expires){var c=a.expires,u=a.expires=new Date;u.setDate(u.getDate()+c)}return t=r.json?JSON.stringify(t):String(t),document.cookie=[r.raw?e:encodeURIComponent(e),"=",r.raw?t:encodeURIComponent(t),a.expires?"; expires="+a.expires.toUTCString():"",a.path?"; path="+a.path:"",a.domain?"; domain="+a.domain:"",a.secure?"; secure":""].join("")}for(var f=r.raw?n:o,d=document.cookie.split("; "),p=e?void 0:{},s=0,m=d.length;s<m;s++){var x=d[s].split("="),l=f(x.shift()),v=f(x.join("="));if(e&&e===l){p=i(v);break}e||(p[l]=i(v))}return p};r.defaults={},$.removeCookie=function(e,n){return void 0!==$.cookie(e)&&($.cookie(e,"",$.extend({},n,{expires:-1})),!0)}}));