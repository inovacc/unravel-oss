!function(e, t){
  "use strict";
  var n=function(e){
    return e&&e.__esModule?e:{
      default:e
    }
  };
  Object.defineProperty(t, "__esModule", {
    value:!0
  });
  var r=n(require("react")), o=n(require("./utils"));
  function a(e){
    var t=e.name, n=e.onClick;
    return r.default.createElement("button", {
      className:"btn-primary", onClick:n
    }, t)
  }function s(e, t){
    if(!e)throw new Error("Invalid input: "+t);
    return o.default.validate(e)
  }t.Button=a;
  t.validate=s;
  t.VERSION="1.0.0";

