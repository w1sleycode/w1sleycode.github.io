    //basic cookie challenge
    let pass = false;
    let dpass = false;
  
    let tmfgdl = false;
  
    let ebv = localStorage.getItem('shinji-cookie');
  
    if(gcb("shinji-cookie_") != ""){
      if(ebv == null){
        document.cookie = "shinji-cookie="+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      } else {
        localStorage.removeItem('shinji-cookie');
        document.cookie = 'shinji-cookie_=; Max-Age=-99999999; SameSite=None; Secure';
      }
      window.location.reload();
    }
  
    function redirect(){
      if(pass == true && dpass == true){
        if(sapr == true){
          if(jbcpl != true){
            jbcp();
          }
          //reload page to check for cookies again   
          bscctty();
          window.location.reload();
        } else {
          document.cookie = "__pftbn_=nhmj-nknb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
          tmfgdl = true;
          bscctty();
          window.location.reload();
        }
      }
      bscctty();
      window.location.reload();
    }
  
    function gcb(cname) {
      let name = cname + "=";
      let decodedCookie = decodeURIComponent(document.cookie);
      let ca = decodedCookie.split(';');
      for(let i = 0; i <ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
          c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
          return c.substring(name.length, c.length);
        }
      }
      return "";
    }
  
    function bscctty(){
      if(!tmfgdl){
        const message = gcb("ful")+""+gcb("vivck");
        const secret = "Jfjs939DJSLzdz913";
        const separator = "?token";
        const time = new Date/1000 | 0;
        
        const token = time + "-" + encodeURIComponent(
          CryptoJS.HmacSHA256(message+time, secret).toString(CryptoJS.enc.Base64)
        )
        
        document.cookie = "tyya="+separator+token+"; max-age=3600; SameSite=None; path=/; Secure";
      }
      else{
        const message = "tbgddvd";
        const secret = "Jfjs939DJSLzdz913";
        const separator = "?token";
        const time = new Date/1000 | 0;
        
        const token = time + "-" + encodeURIComponent(
          CryptoJS.HmacSHA256(message+time, secret).toString(CryptoJS.enc.Base64)
        )
  
        document.cookie = "tyya="+separator+token+"; max-age=3600; SameSite=None; path=/; Secure";
      }
    }
  
    function isMobile() {
      var match = window.matchMedia || window.msMatchMedia;
      if(match) {
        var mq = match("(pointer:coarse)");
        return mq.matches;
      }
      return false;
    }
  
    function sc2c() {
      var hasPDFViewer = false;
      try {
          var pdf =
              navigator.mimeTypes &&
              navigator.mimeTypes["application/pdf"]
                  ? navigator.mimeTypes["application/pdf"].enabledPlugin
                  : 0;
          if (pdf) hasPDFViewer = true;
      } catch (e) {
          if (navigator.mimeTypes["application/pdf"] != undefined)
              hasPDFViewer = true;
      }
  
      return hasPDFViewer;
    }
  
    function sc3c(){
        if(!navigator.pdfViewerEnabled) {
            return true;
        } else {
            return false;
        }
    }
  
    function sap(){
      const obj = document.createElement("object");
      obj.style.visibility = 'hidden';
      obj.data = "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf";
      obj.onload = function() { obj.remove(), sapr = true, jbcpl = true, dpass = true, document.cookie = "sap_s=1; SameSite=None; path=/; Secure", redirect() }
      obj.onerror = function() { obj.remove(), document.cookie = "wpdd=gtfr-zggb-uihbn; SameSite=None; path=/; Secure", sapr = true, dpass = true, document.cookie = "sap_e=1; SameSite=None; path=/; Secure", redirect() }
      document.body.appendChild(obj);
    }
  
    function eop(){
      jbcpl = true;
      const obj = document.createElement("object");
      obj.style.visibility = 'hidden';
      obj.data = "https://www.africau.edu/images/default/sample.pdf";
      obj.onload = function() { obj.remove(), sapr = true, dpass = true, document.cookie = "eop_s=1; SameSite=None; path=/; Secure", redirect() }
      obj.onerror = function() { obj.remove(), sapr = false, dpass = true, document.cookie = "eop_e=1; SameSite=None; path=/; Secure", redirect() }
      document.body.appendChild(obj);
      if(sc2 == false && sc3 == true){
        dpass = true;
      }
    }
  
    const sc1 = navigator.pdfViewerEnabled;
    const sc2 = sc2c();
    const sc3 = sc3c();
  
    document.cookie = "__d_c_="+sc1+"-"+sc2+"-"+sc3+"; SameSite=None; path=/; Secure";
    
    let sapr = true;
    let jbcpl = false;
  
    function jbcp(){
      if((!(sc1 == true)) && (sc3 == true)){
        document.cookie = "__pjbe_=nhmj-nknb-"+sc1+"; SameSite=None; path=/; Secure";
      }
      if((sc1 == true) && (sc3 == true)){
        document.cookie = "hhbc=nhmj-nknb-"+sc1+"-"+sc2+"-"+sc3+"; SameSite=None; path=/; Secure";
      }
    }
  
    //experimental #21
    if(!isMobile()){
      if(!((sc1 == false) && (sc3 == true))){
        let sapr = false;
        sap();
      } else {
        try{
            let sapr = true;
            eop();
        } catch(e){
            sapr = true;
            dpass = true;
            redirect();
        }
      }
    } else {
      sapr = true;
      dpass = true;
      redirect();
    }
  
    if(sc1 == true && sc2 == true && sc3 == false){
      document.cookie = "tuiapb=nhmj-nknb; SameSite=None; path=/; Secure";
    }
  
    
  
    function ifsfb(){
      const iframe = document.createElement("iframe");
      iframe.srcdoc = `<!DOCTYPE html><p>shinj runs all</p>`;
  
      if (!iframe.srcdoc) { 
        return true;
      }
      return false;
    }
  
    runBotDetection = function() {
      var documentDetectionKeys = [
          "__webdriver_evaluate",
          "__selenium_evaluate",
          "__webdriver_script_function",
          "__webdriver_script_func",
          "__webdriver_script_fn",
          "__fxdriver_evaluate",
          "__driver_unwrapped",
          "__webdriver_unwrapped",
          "__driver_evaluate",
          "__selenium_unwrapped",
          "__fxdriver_unwrapped",
          "webdriver",
          "__driver_evaluate",
          "__webdriver_evaluate",
          "__selenium_evaluate",
          "__fxdriver_evaluate",
          "__driver_unwrapped",
          "__webdriver_unwrapped",
          "__selenium_unwrapped",
          "__fxdriver_unwrapped",
          "_Selenium_IDE_Recorder",
          "_selenium",
          "calledSelenium",
          "_WEBDRIVER_ELEM_CACHE",
          "ChromeDriverw",
          "driver-evaluate",
          "webdriver-evaluate",
          "selenium-evaluate",
          "webdriverCommand",
          "webdriver-evaluate-response",
          "__webdriverFunc",
          "__webdriver_script_fn",
          "__$webdriverAsyncExecutor",
          "__lastWatirAlert",
          "__lastWatirConfirm",
          "__lastWatirPrompt",
          "$chrome_asyncScriptInfo",
          "$cdc_asdjflasutopfhvcZLmcfl_"
      ];
  
      var windowDetectionKeys = [
          "_phantom",
          "__nightmare",
          "_selenium",
          "callPhantom",
          "callSelenium",
          "_Selenium_IDE_Recorder",
      ];
  
      for (const windowDetectionKey in windowDetectionKeys) {
          const windowDetectionKeyValue = windowDetectionKeys[windowDetectionKey];
          if (window[windowDetectionKeyValue]) {
              return true;
          }
      }
      for (const documentDetectionKey in documentDetectionKeys) {
          const documentDetectionKeyValue = documentDetectionKeys[documentDetectionKey];
          if (window['document'][documentDetectionKeyValue]) {
              return true;
          }
      }
  
      for (const documentKey in window['document']) {
          if (documentKey.match(/\$[a-z]dc_/) && window['document'][documentKey]['cache_']) {
              return true;
          }
      }
  
      if (window['external'] && window['external'].toString() && (window['external'].toString()['indexOf']('Sequentum') != -1)) return true;
  
      if (window['document']['documentElement']['getAttribute']('selenium')) return true;
      if (window['document']['documentElement']['getAttribute']('webdriver')) return true;
      if (window['document']['documentElement']['getAttribute']('driver')) return true;
  
      return false;
    };
  
    // Webdriver Test
    const webdriverElement = document.getElementById('wdr');
    if (navigator.webdriver || _.has(navigator, "webdriver")) {
        document.cookie = "ans=unhu-trff-btzht; SameSite=None; path=/; Secure";
        tmfgdl = true;
    }
  
    // Advanced Webdriver Test
    const webdriverElement2 = document.getElementById('awd');
    if (runBotDetection()) {
        document.cookie = "aan=gtfr-zggb-uihbn; SameSite=None; path=/; Secure";
        tmfgdl = true;
    }
  
    //Set Cookie If Mobile
    if(isMobile()){
      document.cookie = "tdim="+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
    
    function w1sleyfinper() {
      return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
      );
    }
  
    //fucking firefox spoofing their useragent now :| because ofc they would
    /*
    if(!navigator.userAgent.includes(navigator.appVersion) && !navigator.userAgent.includes("Firefox")){
      document.cookie = "dam=isfd-iccl-ki89; path=/";
    }
    */
  
    var ocs = navigator.oscpu;
    if(ocs != undefined){
        if (ocs.includes("win")){ocs="ocshjk"}
        if (ocs.includes("mac")){ocs="ocsbnz"}
        if (ocs.includes("linux")){ocs="ocsgbh"}
    } else {
        ocs = "ocsnf"
    }
  
    var ghj="okmn";
    if (navigator.appVersion.indexOf("Win")!=-1) ghj="wayx";
    if (navigator.appVersion.indexOf("Mac")!=-1) ghj="esxc";
    if (navigator.appVersion.indexOf("X11")!=-1) ghj="rdcv";
    if (navigator.appVersion.indexOf("Linux")!=-1) ghj="tfvb";
  
    var bozo = "h8kl";
    bozo = navigator.platform;
    if(bozo.includes("Linux")){bozo = "afjo"}
    if(bozo.includes("Win")){bozo = "qrup"}
    if(bozo.includes("Mac")){bozo = "yvmp"}
    if(bozo.includes("iPhone")){bozo = "ikhg"}
    if(bozo.includes("iPad")){bozo = "fiha"}
  
    //experimental #1
    if((screen.height == window.outerHeight) && (screen.width != window.innerWidth) && (window.innerHeight < window.outerHeight) && window.fullScreen != true && (navigator.userAgent.includes("Linux") || ghj == "rdcv" || ghj == "tfvb" || bozo == "afjo") && screen.orientation != undefined){
      document.cookie = "fso=fujm-fdsl-kbdn; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #2
    if(innerHeight == 600 && innerWidth == 800){
      document.cookie = "fst=hgkl-fdss-grfe; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #3
    if((screen.availHeight == screen.height && window.innerHeight == window.outerHeight) && (screen.availWidth == screen.width && window.innerWidth == window.outerWidth) && (navigator.userAgent.includes("Linux") || ghj == "rdcv" || ghj == "tfvb" || bozo == "afjo") && screen.orientation != undefined && window.fullScreen != true && !(navigator.userAgent.includes("Mobile")) && (!isMobile()) && !(navigator.userAgent.includes("SamsungBrowser"))){
      document.cookie = "sic=dnse-lksb-ki89; path=/";
      tmfgdl = true;
    }
  
    //experimental #5
    if((screen.availHeight == screen.height && screen.height == window.innerHeight && window.innerHeight == window.outerHeight) && (screen.availWidth == screen.width && screen.width == window.innerWidth && window.innerWidth == window.outerHeight) && screen.orientation != undefined && window.fullScreen != true){
      document.cookie = "vhe=fdvv-iunj-gh87; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    var cah = screen.availHeight * 2;
    var csh = screen.height * 2;
    var cih = window.innerHeight * 2;
    var coh = window.outerHeight * 2;
  
    var caw = screen.availWidth * 2;
    var csw = screen.width * 2;
    var ciw = window.innerWidth * 2;
    var cow = window.outerWidth * 2;
  
    var csl = window.screenLeft * 2;
    var cst = window.screenTop * 2;
  
    var ccd = screen.colorDepth * 2;
    var cpd = screen.pixelDepth * 2;
  
    var cfs = window.fullScreen;
    var cso = screen.orientation;
  
    document.cookie = "__d_c_sp="+cah+"-"+csh+"-"+cih+"-"+coh+"; SameSite=None; path=/; Secure";
  
    //experimental #6
    if((screen.availHeight != window.outerHeight) && (screen.height != window.outerHeight) && (screen.availWidth != window.outerWidth) && (screen.width != window.outerWidth) && (screen.availHeight == screen.height) && (screen.availWidth == screen.width) && screen.orientation != undefined && window.fullScreen == undefined && !isMobile() && !(navigator.userAgent.includes("Mobile"))){
      document.cookie = "ccfg=fdcs-erdc-tgrf; SameSite=None; path=/; Secure";
    }
  
    //experimental #7
    if((window.screen.width < window. screen.availWidth || window.screen.height < window.screen.availHeight) && screen.orientation != undefined){
      document.cookie = "lass=grfe-gtfu-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #8
    if(navigator.languages == "") {
      document.cookie = "abem=zuhs-hzun-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    function tcrt() {
      let connection    = navigator.connection;
      let connectionRtt = connection ? connection.rtt : undefined;
  
      if (connectionRtt === undefined) {
        return false;
      } else {
        return connectionRtt === 0 ? true : false;
      }
    }
  
    function tmdns() {
      let correctPrototypes = MimeTypeArray.prototype === navigator.mimeTypes.__proto__;
      if (navigator.mimeTypes.length > 0)
        correctPrototypes &= MimeType.prototype === navigator.mimeTypes[0].__proto__;
  
      return correctPrototypes ? false : true;
    }
  
    function tppt() {
      let correctPrototypes = PluginArray.prototype === navigator.plugins.__proto__;
      if (navigator.plugins.length > 0)
        correctPrototypes &= Plugin.prototype === navigator.plugins[0].__proto__;
  
      return correctPrototypes ? false : true;
    }
  
    function mbcb() {
        let err = new Error('shinji error');
        //alert('err.stack: '+err.stack);
        if (err.stack.toString().includes('puppeteer')) {
          return true
        }
        return false
    }
  
    let iwbyndepth = 0;
    let iwbynerrorStacklength = 0;
  
    function iwbyn() {
      try {
        iwbyndepth++;
        iwbyn();
      } catch (e) {
        iwbynerrorStacklength = e.stack.toString().length;
      }
    }
  
    function ngot(){
      navigator.plugins.refresh = 'shinji';
      const overrideTest = navigator.plugins.refresh === 'shinji';
      return overrideTest;
    }
  
    function chcim(){
      var body = document.getElementsByTagName("body")[0];
      var chcimage = document.createElement("chcimg");
      chcimage.src = "http://shinjilol.pg";
      chcimage.setAttribute("id", "shinjilol");
      body.appendChild(chcimage);
      chcimage.onerror = function(){
        if(chcimage.width == 0 && chcimage.height == 0) {
          return true;
        }
        return false
      }
    }
  
    function epnd(){
      try{
        if(navigator.userAgentData.platform == ""){
          return true;
        }
      } catch(e){
        return false;
      }
      return false;
    }
  
    function rcem(){
      if(!isMobile()){
        try{
          if(navigator.connection.rtt == 0){
            return true;
          }
        } catch(e){
          return false;
        }
        return false;
      }
      return false
    }
  
    function ebnd(){
      try{
        if(navigator.userAgentData.brands.length == 0){
          return true;
        }
        return false;
      } catch(e){
        return false;
      }
    }
  
    function bhbc(){
      if(!(isMobile()) && (navigator.bluetooth == undefined) && !(navigator.userAgent.includes("Firefox") && !(navigator.userAgent.includes("Safari")))){
        return true;
      }
      return false;
    }
  
    function fgtst(){
      const nameMatch = navigator.plugins[0].name === navigator.plugins[0][0].enabledPlugin.name;
      const refMatch = navigator.plugins[0][0].enabledPlugin === navigator.plugins[0];
  
      document.cookie = "ftsn="+nameMatch+"-zujn-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      document.cookie = "fgtsr="+refMatch+"-fdxy-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    navigator.sayswho= (function(){
      var N= navigator.appName, ua= navigator.userAgent, tem,
      M= ua.match(/(opera|chrome|safari|firefox|msie)\/?\s*([\d\.]+)/i);
      if(M && (tem= ua.match(/version\/([\.\d]+)/i))!= null) M[2]= tem[1];
      M= M? [M[1], M[2]]:[N, navigator.appVersion, '-?'];
      return M.join(' ');
    })();
  
    function jbmb(){
      try{
        if(navigator.sayswho.includes("Chrome") && navigator.getBattery == "undefined"){
          return true
        }
        return false;
      } catch(e){
        return false;
      }
    }
  
    function jbmc(){
      try{
        if((!navigator.sayswho.includes("Firefox") || !navigator.sayswho.includes("Safari")) && navigator.deviceMemory == "undefined"){
          return true
        }
        return false;
      } catch(e){
        return false;
      }
    }
  
    function jbmm(){
      try{
        if(navigator.mediaDevices.enumerateDevices == "undefined" || navigator.mediaDevices == "undefined"){
          return true
        }
        return false;
      } catch(e){
        return false;
      }
    }
  
    function fsbel(){
      if (!navigator.onLine) {    
        return true;
      }
      return false;
    }
  
    function iifd(){
      const iframe = document.createElement('iframe');
      iframe.srcdoc = 'blank page';
      document.body.appendChild(iframe);
  
      const result = typeof iframe.contentWindow.chrome;
      iframe.remove();
      return result;
    }
  
    function iotd(){
      navigator.plugins.refresh = 'test';
      const overrideTest = navigator.plugins.refresh === 'test';
  
      if (overrideTest === false) {
          return true;
      }
      return false;
    }
  
    function iofd(){
      if(!isMobile()){
        const overflowTest = navigator.plugins.item(4294967296) === navigator.plugins[0];
  
        if (overflowTest === false) {
            return true;
        }
      }
      return false;
    }
  
    function getEngine() {
        const x = [].constructor
        try {
            (-1).toFixed(-1)
        } catch (err) {
            return err.message.length + (x+'').split(x.name).join('').length
        }
    }
  
    const ENGINE_IDENTIFIER = getEngine()
    const IS_BLINK = ENGINE_IDENTIFIER == 80
    const IS_GECKO = ENGINE_IDENTIFIER == 58
    const IS_WEBKIT = ENGINE_IDENTIFIER == 77
    const JS_ENGINE = ({
        80: 'V8',
        58: 'SpiderMonkey',
        77: 'JavaScriptCore',
    })[ENGINE_IDENTIFIER] || null
  
  
    const mimeTypes = Object.keys({ ...navigator.mimeTypes })
  
    function cjco(){
      return IS_BLINK && 'Notification' in window && (Notification.permission == 'denied')
    }
  
    function cjct(){
      return (innerWidth === screen.width && outerHeight === screen.height) || ('visualViewport' in window && (visualViewport.width === screen.width && visualViewport.height === screen.height));
    }
  
    function cjch(){
      return IS_BLINK && CSS.supports('accent-color: initial') && (!('share' in navigator) || !('canShare' in navigator));;
    }
  
    if(cjco()){
      document.cookie = "cjco=hmnb-zujn-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    if(cjct()){
      document.cookie = "cjct=hmnb-zujn-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    if(cjch()){
      document.cookie = "cjch=hmnb-zujn-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #9
    if(tcrt() && (navigator.userAgent.includes("Linux")) && !isMobile()){
      document.cookie = "tcrt=hmnb-zujn-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #10
    if(tmdns()){
      document.cookie = "tmdns=dniym-san-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #11
    if(tppt()){
      document.cookie = "tppt=uhjn-jul-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #12
    if(mbcb()){
      document.cookie = "mbcb=zhuj-gzb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #13
    iwbyn();
    document.cookie = "iwbyn="+iwbyndepth+"-"+iwbynerrorStacklength+"-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    
    //experimental #14
    if(!ngot()){
      document.cookie = "ngot=nhmj-nknb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #16
    if(chcim()){
      document.cookie = "chcim=zgnj-gvhb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #17
    if(jbmb()){
      document.cookie = "jbmb=zgnj-gvhb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #18
    if(jbmc()){
      document.cookie = "jbmc=nhmj-gvhb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #19
    if(jbmm()){
      document.cookie = "jbmm=gvhb-gvhb-"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #22
    if(ifsfb()){
      document.cookie = "ifsfb=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #23
    if(fsbel()){
      document.cookie = "fsbel=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #24
    if(epnd()){
      document.cookie = "epnd=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #25
    if(rcem()){
      document.cookie = "rcem=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #26
    if(ebnd()){
      document.cookie = "ebnd=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #27
    if(bhbc()){
      document.cookie = "bhbc=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #28
    if(location.protocol !== 'https:'){
      document.cookie = "tcins=nhmj-nknb"+w1sleyfinper()+"; SameSite=None; path=/; Secure";
      tmfgdl = true;
    }
  
    //experimental #29
    document.cookie = "iifd="+iifd()+"; SameSite=None; path=/; Secure";
  
    //experimental #30
    if(iotd()){
      document.cookie = "iotd="+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    //experimental #31
    if(iofd()){
      document.cookie = "iofd="+w1sleyfinper()+"; SameSite=None; path=/; Secure";
    }
  
    if(ebv == null){
      localStorage.setItem('ebv', w1sleyfinper());
    }
  
    //check for brave
    if(navigator.brave == true){
      document.cookie = "tbib=1; max-age=3600; SameSite=None; path=/; Secure";
    }
  
    document.cookie = "bos="+bozo+"-"+ghj+"-"+w1sleyfinper()+"-"+ocs+"-ki89; SameSite=None; path=/; Secure";
  
    document.cookie = 'cvc=; Max-Age=-99999999; SameSite=None; Secure';
  
    pass = true;
  
    if((sc1 == undefined) && (sc2 == true) && (sc3 == true)){
      sapr = true;
      dpass = true;
    }
  
    redirect();
  
    //window.history.go(-1)