"use strict";(self.webpackChunkkubernetes_dashboard=self.webpackChunkkubernetes_dashboard||[]).push([[10],{2010:(E,r,e)=>{e.r(r),e.d(r,{RoleModule:()=>j});var d=e(7833),m=e(5816),a=e(8109),h=e(5103),p=e(960),f=e(3201),s=e(5879),l=e(8803),v=e(1234),c=e(4707),R=e(6190),y=e(1993),z=e(2794),C=e(1647);let I=(()=>{class t{constructor(i,o,n,N){this.role_=i,this.actionbar_=o,this.route_=n,this.notifications_=N,this.endpoint_=c.wE.resource(c._z.role,!0),this.isInitialized=!1,this.destroyRef=(0,s.f3M)(s.ktI)}ngOnInit(){const i=this.route_.snapshot.params.resourceName,o=this.route_.snapshot.params.resourceNamespace;this.role_.get(this.endpoint_.detail(),i,o).pipe((0,y.sL)(this.destroyRef)).subscribe(n=>{this.role=n,this.notifications_.pushErrors(n.errors),this.actionbar_.onInit.emit(new l.N("Role",n.objectMeta,n.typeMeta)),this.isInitialized=!0})}ngOnDestroy(){this.actionbar_.onDetailsLeave.emit()}static#t=this.\u0275fac=function(o){return new(o||t)(s.Y36(R.p),s.Y36(l.b),s.Y36(a.gz),s.Y36(v.TF))};static#e=this.\u0275cmp=s.Xpm({type:t,selectors:[["kd-role-detail"]],decls:2,vars:4,consts:[[3,"initialized","objectMeta"],[3,"rules","initialized"]],template:function(o,n){1&o&&s._UZ(0,"kd-object-meta",0)(1,"kd-policy-rule-list",1),2&o&&(s.Q6J("initialized",n.isInitialized)("objectMeta",null==n.role?null:n.role.objectMeta),s.xp6(1),s.Q6J("rules",null==n.role?null:n.role.rules)("initialized",n.isInitialized))},dependencies:[z.A,C.V],encapsulation:2})}return t})();var L=e(2501);const u={path:"",component:(()=>{class t{static#t=this.\u0275fac=function(o){return new(o||t)};static#e=this.\u0275cmp=s.Xpm({type:t,selectors:[["kd-role-list-state"]],decls:1,vars:0,template:function(o,n){1&o&&s._UZ(0,"kd-role-list")},dependencies:[L.C],encapsulation:2})}return t})(),data:{breadcrumb:p.SX.Roles,parent:f.a}},M={path:":resourceNamespace/:resourceName",component:I,data:{breadcrumb:"{{ resourceName }}",parent:u}};let g=(()=>{class t{static#t=this.\u0275fac=function(o){return new(o||t)};static#e=this.\u0275mod=s.oAB({type:t});static#s=this.\u0275inj=s.cJS({imports:[a.Bz.forChild([u,M,h.aA]),a.Bz]})}return t})(),j=(()=>{class t{static#t=this.\u0275fac=function(o){return new(o||t)};static#e=this.\u0275mod=s.oAB({type:t});static#s=this.\u0275inj=s.cJS({imports:[m.m,d.K,g]})}return t})()}}]);