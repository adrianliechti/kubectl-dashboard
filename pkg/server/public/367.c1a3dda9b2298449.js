"use strict";(self.webpackChunkkubernetes_dashboard=self.webpackChunkkubernetes_dashboard||[]).push([[367],{2367:(Ot,y,i)=>{i.r(y),i.d(y,{SecretModule:()=>bt});var Q=i(7833),w=i(5816),E=i(8109),V=i(5103),W=i(960),q=i(3842),e=i(5879),A=i(2844),R=i(8803),tt=i(1234),M=i(4707),et=i(6190),nt=i(1993),v=i(7143),_=i(6814),ot=i(6484),rt=i(2794),b=i(4525),O=i(9862),st=i(8584);const l="function"==typeof Buffer,D=("function"==typeof TextDecoder&&new TextDecoder,"function"==typeof TextEncoder?new TextEncoder:void 0),u=Array.prototype.slice.call("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),a=((t=>{let o={};t.forEach((n,r)=>o[n]=r)})(u),String.fromCharCode.bind(String)),F=("function"==typeof Uint8Array.from&&Uint8Array.from.bind(Uint8Array),t=>t.replace(/=/g,"").replace(/[+\/]/g,o=>"+"==o?"-":"_")),C="function"==typeof btoa?t=>btoa(t):l?t=>Buffer.from(t,"binary").toString("base64"):t=>{let o,n,r,s,c="";const f=t.length%3;for(let g=0;g<t.length;){if((n=t.charCodeAt(g++))>255||(r=t.charCodeAt(g++))>255||(s=t.charCodeAt(g++))>255)throw new TypeError("invalid character found");o=n<<16|r<<8|s,c+=u[o>>18&63]+u[o>>12&63]+u[o>>6&63]+u[63&o]}return f?c.slice(0,f-3)+"===".substring(f):c},m=l?t=>Buffer.from(t).toString("base64"):t=>{let n=[];for(let r=0,s=t.length;r<s;r+=4096)n.push(a.apply(null,t.subarray(r,r+4096)));return C(n.join(""))},dt=t=>{if(t.length<2)return(o=t.charCodeAt(0))<128?t:o<2048?a(192|o>>>6)+a(128|63&o):a(224|o>>>12&15)+a(128|o>>>6&63)+a(128|63&o);var o=65536+1024*(t.charCodeAt(0)-55296)+(t.charCodeAt(1)-56320);return a(240|o>>>18&7)+a(128|o>>>12&63)+a(128|o>>>6&63)+a(128|63&o)},lt=/[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g,$=l?t=>Buffer.from(t,"utf8").toString("base64"):D?t=>m(D.encode(t)):t=>C((t=>t.replace(lt,dt))(t));var gt=i(8189),S=i(6223),Et=i(1075),_t=i(6005),Ct=i(4368),mt=i(5565);function xt(t,o){if(1&t){const n=e.EpF();e.TgZ(0,"div",1)(1,"mat-form-field",2)(2,"textarea",3),e.NdJ("ngModelChange",function(s){e.CHM(n);const c=e.oxw();return e.KtG(c.text=s)}),e.qZA()(),e.TgZ(3,"div",4)(4,"button",5),e.NdJ("click",function(){e.CHM(n);const s=e.oxw();return e.KtG(s.update())}),e.SDv(5,6),e.qZA(),e.TgZ(6,"button",7),e.NdJ("click",function(){e.CHM(n);const s=e.oxw();return e.KtG(s.cancel())}),e.SDv(7,8),e.qZA()()()}if(2&t){const n=e.oxw();e.xp6(2),e.Q6J("ngModel",n.text)}}let Tt=(()=>{class t{set editing(n){this.editing_=n,this.updateText_()}get editing(){return this.editing_}set secret(n){this.secret_=n}get secret(){return this.secret_}constructor(n,r,s){this.dialog_=n,this.http_=r,this.decoder_=s,this.closeEvent=new e.vpe,this.text="",this.editing_=!1}ngOnInit(){this.updateText_()}update(){const n=b.r.getUrl(this.secret.typeMeta,this.secret.objectMeta);this.http_.get(n).toPromise().then(r=>{const s=this.encode_(this.text);r.data[this.key]=s;const c=b.r.getUrl(this.secret.typeMeta,this.secret.objectMeta);this.http_.put(c,r,{headers:this.getHttpHeaders_(),responseType:"text"}).subscribe(()=>{this.secret_.data[this.key]=s,this.closeEvent.emit(!0)},this.handleErrorResponse_.bind(this))})}cancel(){this.closeEvent.emit(!0)}updateText_(){this.text=this.secret&&this.key?this.decoder_.base64(this.secret.data[this.key]):""}encode_(n){return((t,o=!1)=>o?F($(t)):$(t))(n,!1)}getHttpHeaders_(){const n=new O.WM;return n.set("Content-Type","application/json"),n.set("Accept","application/json"),n}handleErrorResponse_(n){n&&this.dialog_.open(st.h,{width:"630px",data:{title:"OK"===n.statusText?"Internal server error":n.statusText,message:n.error||"Could not perform the operation.",confirmLabel:"OK"}})}static#t=this.\u0275fac=function(r){return new(r||t)(e.Y36(gt.uw),e.Y36(O.eN),e.Y36(v.F))};static#e=this.\u0275cmp=e.Xpm({type:t,selectors:[["kd-secret-detail-edit"]],inputs:{key:"key",editing:"editing",secret:"secret"},outputs:{closeEvent:"closeEvent"},decls:1,vars:1,consts:function(){let n,r;return n=" Update ",r=" Cancel ",[["class","kd-secret-detail-edit-container",4,"ngIf"],[1,"kd-secret-detail-edit-container"],[1,"kd-secret-detail-text"],["cdkTextareaAutosize","","cdkAutosizeMinRows","1","cdkAutosizeMaxRows","20","matInput","",3,"ngModel","ngModelChange"],[1,"kd-secret-detail-actions"],["mat-raised-button","","color","primary","id","confirm-edit",3,"click"],n,["mat-button","","color","primary",3,"click"],r]},template:function(r,s){1&r&&e.YNc(0,xt,8,1,"div",0),2&r&&e.Q6J("ngIf",s.secret)},dependencies:[_.O5,S.Fj,S.JJ,S.On,Et.lW,_t.KE,Ct.IC,mt.Nt],styles:[".kd-secret-detail-text[_ngcontent-%COMP%]{width:100%}.kd-secret-detail-text[_ngcontent-%COMP%]   .mat-input-element[_ngcontent-%COMP%]{font-family:Roboto Mono Regular,monospace;font-size:14px}.kd-secret-detail-actions[_ngcontent-%COMP%]{min-height:52px;padding:8px 0}"]})}return t})();function St(t,o){if(1&t){const n=e.EpF();e.TgZ(0,"kd-hidden-property",7,8)(2,"div",9),e._uU(3),e.qZA(),e.TgZ(4,"div",10),e._uU(5),e.qZA(),e.TgZ(6,"div",11)(7,"kd-secret-detail-edit",12),e.NdJ("closeEvent",function(){e.CHM(n);const s=e.MAs(1),c=e.oxw();return e.KtG(s.mode=c.HiddenPropertyMode.Hidden)}),e.qZA()(),e.TgZ(8,"div",13),e._uU(9),e.qZA()()}if(2&t){const n=o.$implicit,r=e.MAs(1),s=e.oxw();e.Q6J("enableEdit",!0),e.xp6(3),e.Oqu(n),e.xp6(2),e.hij(" ",s.decoder.base64(null==s.secret?null:s.secret.data[n])," "),e.xp6(2),e.Q6J("secret",s.secret)("key",n)("editing",r.mode==s.HiddenPropertyMode.Edit),e.xp6(2),e.hij("",s.decoder.base64(null==s.secret?null:s.secret.data[n]).length," bytes")}}function yt(t,o){1&t&&(e.ynx(0),e.SDv(1,14),e.BQk())}let At=(()=>{class t{constructor(n,r,s,c,f){this.secret_=n,this.actionbar_=r,this.activatedRoute_=s,this.notifications_=c,this.decoder=f,this.endpoint_=M.wE.resource(M._z.secret,!0),this.isInitialized=!1,this.HiddenPropertyMode=A.C,this.destroyRef=(0,e.f3M)(e.ktI)}ngOnInit(){const n=this.activatedRoute_.snapshot.params.resourceName,r=this.activatedRoute_.snapshot.params.resourceNamespace;this.secret_.get(this.endpoint_.detail(),n,r).pipe((0,nt.sL)(this.destroyRef)).subscribe(s=>{this.secret=s,this.notifications_.pushErrors(s.errors),this.actionbar_.onInit.emit(new R.N("Secret",s.objectMeta,s.typeMeta)),this.isInitialized=!0})}ngOnDestroy(){this.actionbar_.onDetailsLeave.emit()}getDataKeys(){return this.secret&&this.secret.data?Object.keys(this.secret.data):[]}static#t=this.\u0275fac=function(r){return new(r||t)(e.Y36(et.p),e.Y36(R.b),e.Y36(E.gz),e.Y36(tt.TF),e.Y36(v.F))};static#e=this.\u0275cmp=e.Xpm({type:t,selectors:[["kd-secret-detail"]],decls:7,vars:5,consts:function(){let n,r;return n=" Data ",r="There is no data to display.",[[3,"initialized","objectMeta"],[3,"initialized"],["title",""],n,["content",""],[3,"enableEdit",4,"ngFor","ngForOf"],[4,"ngIf"],[3,"enableEdit"],["property",""],["key",""],["whenVisible","",1,"kd-code-block"],["whenEdit",""],[3,"secret","key","editing","closeEvent"],["whenHidden",""],r]},template:function(r,s){1&r&&(e._UZ(0,"kd-object-meta",0),e.TgZ(1,"kd-card",1)(2,"div",2),e.SDv(3,3),e.qZA(),e.TgZ(4,"div",4),e.YNc(5,St,10,7,"kd-hidden-property",5),e.YNc(6,yt,2,0,"ng-container",6),e.qZA()()),2&r&&(e.Q6J("initialized",s.isInitialized)("objectMeta",null==s.secret?null:s.secret.objectMeta),e.xp6(1),e.Q6J("initialized",s.isInitialized),e.xp6(4),e.Q6J("ngForOf",s.getDataKeys()),e.xp6(1),e.Q6J("ngIf",!(null!=s.secret&&s.secret.data)))},dependencies:[_.sg,_.O5,ot.A,A.U,rt.A,Tt],encapsulation:2})}return t})();var Rt=i(682);const K={path:"",component:(()=>{class t{static#t=this.\u0275fac=function(r){return new(r||t)};static#e=this.\u0275cmp=e.Xpm({type:t,selectors:[["kd-secret-list-state"]],decls:1,vars:0,consts:function(){let n;return n="Secrets",[["title",n]]},template:function(r,s){1&r&&e._UZ(0,"kd-secret-list",0)},dependencies:[Rt.A],encapsulation:2})}return t})(),data:{breadcrumb:W.SX.Secrets,parent:q.M}},Mt={path:":resourceNamespace/:resourceName",component:At,data:{breadcrumb:"{{ resourceName }}",parent:K}};let vt=(()=>{class t{static#t=this.\u0275fac=function(r){return new(r||t)};static#e=this.\u0275mod=e.oAB({type:t});static#n=this.\u0275inj=e.cJS({imports:[E.Bz.forChild([K,Mt,V.aA]),E.Bz]})}return t})(),bt=(()=>{class t{static#t=this.\u0275fac=function(r){return new(r||t)};static#e=this.\u0275mod=e.oAB({type:t});static#n=this.\u0275inj=e.cJS({imports:[w.m,Q.K,vt]})}return t})()}}]);