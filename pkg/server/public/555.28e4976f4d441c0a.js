"use strict";(self.webpackChunkkubernetes_dashboard=self.webpackChunkkubernetes_dashboard||[]).push([[555],{3555:(G,m,a)=>{a.r(m),a.d(m,{NamespaceModule:()=>X});var E=a(7833),h=a(5816),s=a(8109),C=a(960),M=a(3201),t=a(5879),N=a(5529),c=a(1993),l=a(8803),d=a(6814),v=a(1075),T=a(4692),A=a(695),u=a(3814),g=a(4351);function R(e,p){if(1&e&&t._UZ(0,"kd-actionbar-detail-actions",4),2&e){const n=t.oxw(2);t.Q6J("objectMeta",n.resourceMeta.objectMeta)("typeMeta",n.resourceMeta.typeMeta)("displayName",n.resourceMeta.displayName)}}function S(e,p){if(1&e){const n=t.EpF();t.TgZ(0,"div",1)(1,"button",2),t.NdJ("click",function(){t.CHM(n);const o=t.oxw();return t.KtG(o.onClick())}),t.TgZ(2,"mat-icon"),t._uU(3,"description"),t.qZA()(),t.YNc(4,R,1,3,"kd-actionbar-detail-actions",3),t.qZA()}if(2&e){const n=t.oxw();t.xp6(4),t.Q6J("ngIf",n.isInitialized)}}let I=(()=>{class e{constructor(n,i){this.actionbar_=n,this.router_=i,this.isInitialized=!1,this.isVisible=!1,this.destroyRef=(0,t.f3M)(t.ktI)}ngOnInit(){this.actionbar_.onInit.pipe((0,c.sL)(this.destroyRef)).subscribe(n=>{this.resourceMeta=n,this.isInitialized=!0,this.isVisible=!0}),this.actionbar_.onDetailsLeave.pipe((0,c.sL)(this.destroyRef)).subscribe(()=>this.isVisible=!1)}onClick(){this.router_.navigate(["workloads"],{queryParamsHandling:"merge",queryParams:{[N.xt]:this.resourceMeta.objectMeta.name}})}static#t=this.\u0275fac=function(i){return new(i||e)(t.Y36(l.b),t.Y36(s.F0))};static#e=this.\u0275cmp=t.Xpm({type:e,selectors:[["ng-component"]],decls:1,vars:1,consts:function(){let n;return n="Go to namespace",[["fxLayout","row",4,"ngIf"],["fxLayout","row"],["mat-icon-button","","color","accent","matTooltip",n,1,"kd-toolbar-action",3,"click"],[3,"objectMeta","typeMeta","displayName",4,"ngIf"],[3,"objectMeta","typeMeta","displayName"]]},template:function(i,o){1&i&&t.YNc(0,S,5,1,"div",0),2&i&&t.Q6J("ngIf",o.isVisible)},dependencies:[d.O5,v.lW,T.Hw,A.gM,u.xw,g.$],encapsulation:2})}return e})();var y=a(1234),r=a(4707),L=a(6190),O=a(6484),b=a(2141),z=a(2794),_=a(5421),x=a(4943),U=a(8099);function Z(e,p){if(1&e&&(t.TgZ(0,"kd-property")(1,"div",10),t.SDv(2,11),t.qZA(),t.TgZ(3,"div",12),t._uU(4),t.qZA()()),2&e){const n=t.oxw(2);t.xp6(4),t.Oqu(null==n.namespace?null:n.namespace.phase)}}function D(e,p){if(1&e&&(t.TgZ(0,"div",8),t.YNc(1,Z,5,1,"kd-property",9),t.qZA()),2&e){const n=t.oxw();t.xp6(1),t.Q6J("ngIf",null==n.namespace?null:n.namespace.phase)}}let P=(()=>{class e{constructor(n,i,o,Y){this.namespace_=n,this.actionbar_=i,this.activatedRoute_=o,this.notifications_=Y,this.endpoint_=r.wE.resource(r._z.namespace),this.isInitialized=!1,this.destroyRef=(0,t.f3M)(t.ktI)}ngOnInit(){const n=this.activatedRoute_.snapshot.params.resourceName;this.eventListEndpoint=this.endpoint_.child(n,r._z.event),this.namespace_.get(this.endpoint_.detail(),n).pipe((0,c.sL)(this.destroyRef)).subscribe(i=>{this.namespace=i,this.notifications_.pushErrors(i.errors),this.actionbar_.onInit.emit(new l.N("Namespace",i.objectMeta,i.typeMeta)),this.isInitialized=!0})}ngOnDestroy(){this.actionbar_.onDetailsLeave.emit()}static#t=this.\u0275fac=function(i){return new(i||e)(t.Y36(L.z),t.Y36(l.b),t.Y36(s.gz),t.Y36(y.TF))};static#e=this.\u0275cmp=t.Xpm({type:e,selectors:[["kd-namespace-detail"]],decls:8,vars:9,consts:function(){let n,i;return n=" Resource information ",i=" Status ",[[3,"initialized","objectMeta"],[3,"initialized"],["title",""],n,["content","","fxLayout","row wrap",4,"ngIf"],[3,"quotas","initialized"],[3,"limits","initialized"],[3,"endpoint"],["content","","fxLayout","row wrap"],[4,"ngIf"],["key",""],i,["value",""]]},template:function(i,o){1&i&&(t._UZ(0,"kd-object-meta",0),t.TgZ(1,"kd-card",1)(2,"div",2),t.SDv(3,3),t.qZA(),t.YNc(4,D,2,1,"div",4),t.qZA(),t._UZ(5,"kd-resource-quota-list",5)(6,"kd-resource-limit-list",6)(7,"kd-event-list",7)),2&i&&(t.Q6J("initialized",o.isInitialized)("objectMeta",null==o.namespace?null:o.namespace.objectMeta),t.xp6(1),t.Q6J("initialized",o.isInitialized),t.xp6(3),t.Q6J("ngIf",o.isInitialized),t.xp6(1),t.Q6J("quotas",null==o.namespace||null==o.namespace.resourceQuotaList?null:o.namespace.resourceQuotaList.items)("initialized",o.isInitialized),t.xp6(1),t.Q6J("limits",null==o.namespace?null:o.namespace.resourceLimits)("initialized",o.isInitialized),t.xp6(1),t.Q6J("endpoint",o.eventListEndpoint))},dependencies:[d.O5,u.xw,O.A,b.X,z.A,_.s,x.R,U.i],encapsulation:2})}return e})();var $=a(4649);const f={path:"",component:(()=>{class e{static#t=this.\u0275fac=function(i){return new(i||e)};static#e=this.\u0275cmp=t.Xpm({type:e,selectors:[["kd-namespace-list-view"]],decls:1,vars:0,template:function(i,o){1&i&&t._UZ(0,"kd-namespace-list")},dependencies:[$.q],encapsulation:2})}return e})(),data:{breadcrumb:C.SX.Namespaces,parent:M.a}},j={path:":resourceName",component:P,data:{breadcrumb:"{{ resourceName }}",parent:f}},J={path:"",component:I,outlet:"actionbar"};let Q=(()=>{class e{static#t=this.\u0275fac=function(i){return new(i||e)};static#e=this.\u0275mod=t.oAB({type:e});static#n=this.\u0275inj=t.cJS({imports:[s.Bz.forChild([f,j,J]),s.Bz]})}return e})(),X=(()=>{class e{static#t=this.\u0275fac=function(i){return new(i||e)};static#e=this.\u0275mod=t.oAB({type:e});static#n=this.\u0275inj=t.cJS({imports:[h.m,E.K,Q]})}return e})()}}]);