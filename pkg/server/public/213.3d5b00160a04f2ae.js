"use strict";(self.webpackChunkkubernetes_dashboard=self.webpackChunkkubernetes_dashboard||[]).push([[213],{2213:(x,c,o)=>{o.r(c),o.d(c,{OverviewModule:()=>D});var g=o(7833),u=o(5816),p=o(8109),v=o(960),a=o(4321),_=o(2759),e=o(5879),h=o(6814),m=o(976),T=o(8506),C=o(9901),f=o(844),O=o(9963),Z=o(7502),J=o(2065),N=o(6063),E=o(2590),S=o(1830),k=o(4649),A=o(2983),M=o(8041),R=o(8722),L=o(6630),Q=o(2325),U=o(5747),$=o(1223),V=o(682),I=o(9859),y=o(7402),W=o(3986),w=o(0),b=o(4060),G=o(2501),X=o(224);function j(i,F){if(1&i&&e._UZ(0,"kd-workload-statuses",10),2&i){const r=e.oxw();e.Q6J("resourcesRatio",r.resourcesRatio)}}const z={path:"",component:(()=>{class i extends _.v{hasCluster(){return this.isGroupVisible(a.l.cluster)}hasWorkloads(){return this.isGroupVisible(a.l.workloads)}hasDiscovery(){return this.isGroupVisible(a.l.discovery)}hasConfig(){return this.isGroupVisible(a.l.config)}showWorkloadStatuses(){return 0!==Object.values(this.resourcesRatio).reduce((r,l)=>r+l.length,0)}static#e=this.\u0275fac=function(){let r;return function(t){return(r||(r=e.n5z(i)))(t||i)}}();static#n=this.\u0275cmp=e.Xpm({type:i,selectors:[["kd-overview"]],features:[e.qOj],decls:40,vars:32,consts:function(){let r,l,t,s,n;return r=" Workloads\n",l=" Service\n",t=" Config and Storage\n",s="Secrets",n=" Cluster ",[[1,"kd-card-group-header","kd-muted",3,"hidden"],r,[3,"metrics"],[3,"resourcesRatio",4,"ngIf"],[3,"hideable","onchange"],l,t,["title",s,3,"hideable","onchange"],[3,"hidden"],n,[3,"resourcesRatio"]]},template:function(l,t){1&l&&(e.TgZ(0,"div",0),e.SDv(1,1),e.qZA(),e.TgZ(2,"div"),e._UZ(3,"kd-graph-metrics",2),e.YNc(4,j,1,1,"kd-workload-statuses",3),e.TgZ(5,"kd-cron-job-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(6,"kd-daemon-set-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(7,"kd-deployment-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(8,"kd-job-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(9,"kd-pod-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(10,"kd-replica-set-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(11,"kd-replication-controller-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(12,"kd-stateful-set-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA()(),e.TgZ(13,"div",0),e.SDv(14,5),e.qZA(),e.TgZ(15,"div")(16,"kd-ingress-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(17,"kd-ingress-class-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(18,"kd-service-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA()(),e.TgZ(19,"div",0),e.SDv(20,6),e.qZA(),e.TgZ(21,"div")(22,"kd-config-map-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(23,"kd-persistent-volume-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(24,"kd-secret-list",7),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(25,"kd-storage-class-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA()(),e.TgZ(26,"div",8)(27,"div",0),e.SDv(28,9),e.qZA(),e.TgZ(29,"div")(30,"kd-cluster-role-binding-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(31,"kd-cluster-role-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(32,"kd-namespace-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(33,"kd-network-policy-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(34,"kd-node-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(35,"kd-persistent-volume-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(36,"kd-role-binding-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(37,"kd-role-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA(),e.TgZ(38,"kd-service-account-list",4),e.NdJ("onchange",function(n){return t.onListUpdate(n)}),e.qZA()()(),e._UZ(39,"kd-zero-state",8)),2&l&&(e.Q6J("hidden",!t.hasWorkloads()),e.xp6(3),e.Q6J("metrics",t.cumulativeMetrics),e.xp6(1),e.Q6J("ngIf",t.showWorkloadStatuses()),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hidden",!t.hasDiscovery()),e.xp6(3),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hidden",!t.hasConfig()),e.xp6(3),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hidden",t.shouldShowZeroState()),e.xp6(1),e.Q6J("hidden",!t.hasCluster()),e.xp6(3),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hideable",!0),e.xp6(1),e.Q6J("hidden",!t.shouldShowZeroState()))},dependencies:[h.O5,m.z,T.u,C.o,f.d,O.w,Z.M,J.y,N.j,E._,S.Q,k.q,A.v,M.x,R.p,L.$,Q._,U.c,$.e,V.A,I.$,y.S,W.f,w.H,b.j,G.C,X.T],encapsulation:2})}return i})(),data:{breadcrumb:v.SX.Overview}};let P=(()=>{class i{static#e=this.\u0275fac=function(l){return new(l||i)};static#n=this.\u0275mod=e.oAB({type:i});static#t=this.\u0275inj=e.cJS({imports:[p.Bz.forChild([z]),p.Bz]})}return i})(),D=(()=>{class i{static#e=this.\u0275fac=function(l){return new(l||i)};static#n=this.\u0275mod=e.oAB({type:i});static#t=this.\u0275inj=e.cJS({imports:[u.m,g.K,P]})}return i})()}}]);