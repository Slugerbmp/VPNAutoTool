// Значок NETtool в строке меню macOS (JavaScript for Automation).
// Запускается программой: osascript -l JavaScript menubar.js <адрес> <иконка>
ObjC.import('Cocoa');

function run(argv) {
  var base = argv[0];
  var iconPath = argv[1];
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);

  var fails = 0;
  function get(path) {
    var url = $.NSURL.URLWithString(base + path);
    var data = $.NSData.dataWithContentsOfURL(url);
    if (!data || data.isNil()) return null;
    var str = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
    try { return JSON.parse(ObjC.unwrap(str)); } catch (e) { return {}; }
  }

  var item = $.NSStatusBar.systemStatusBar.statusItemWithLength($.NSVariableStatusItemLength);
  var img = $.NSImage.alloc.initWithContentsOfFile(iconPath);
  if (img && !img.isNil()) {
    img.setSize($.NSMakeSize(18, 18));
    img.setTemplate(true);
    item.button.setImage(img);
  } else {
    item.button.setTitle('VPN');
  }

  var miStatus, miServer, miToggle, miRu, srvMenu;
  var lastNames = '', names = [];

  function rebuildServers(st) {
    var list = st.servers || [];
    var key = JSON.stringify(list.map(function (s) { return s.name; })) + '|' + st.pinned;
    srvMenu.removeAllItems;
    var auto = mi('⚡ Авто — самый стабильный', 'pickServer:');
    auto.setTag(-1);
    auto.setState(st.pinned ? 0 : 1);
    srvMenu.addItem(auto);
    if (list.length) srvMenu.addItem($.NSMenuItem.separatorItem);
    names = [];
    list.forEach(function (s, i) {
      names.push(s.name);
      var t = s.name + (s.ping > 0 ? '    ' + s.ping + ' мс' : s.ping < 0 ? '    нет связи' : '');
      if (i === st.cur && !st.pinned) t = '● ' + t;
      var it = mi(t, 'pickServer:');
      it.setTag(i);
      it.setState(st.pinned === s.name ? 1 : 0);
      srvMenu.addItem(it);
    });
    srvMenu.addItem($.NSMenuItem.separatorItem);
    srvMenu.addItem(mi('Обновить подписку', 'refreshSub:'));
    miRu = mi('Российские сайты без VPN', 'toggleRu:');
    miRu.setState(st.directRu ? 1 : 0);
    srvMenu.addItem(miRu);
    lastNames = key;
  }

  function refresh() {
    var st = get('/api/state?src=tray');
    if (!st) {
      if (++fails >= 3) app.terminate(null); // программа закрылась — убираем значок
      return;
    }
    fails = 0;
    var cur = (st.servers && st.cur >= 0 && st.servers[st.cur]) ? st.servers[st.cur] : null;
    miStatus.setTitle(st.on ? 'VPN включён' : 'VPN выключен');
    var srv = 'Сервер не выбран';
    if (cur) srv = cur.name + (cur.ping > 0 ? ' · ' + cur.ping + ' мс' : '');
    else if (st.error) srv = 'Ошибка — откройте окно';
    miServer.setTitle(srv);
    miToggle.setTitle(st.on ? 'Выключить VPN' : 'Включить VPN');
    rebuildServers(st);
    miToggle.setEnabled(!!(st.on || (st.core && cur)));
    item.button.setAppearsDisabled(!st.on);
    item.button.setToolTip('NETtool — ' + (st.on ? 'включён' : 'выключен') + (cur ? '\n' + srv : ''));
  }

  ObjC.registerSubclass({
    name: 'VPNAutoMenuTarget',
    methods: {
      'openUI:': { types: ['void', ['id']], implementation: function (s) { get('/api/tray?do=open'); } },
      'toggle:': { types: ['void', ['id']], implementation: function (s) { get('/api/tray?do=toggle'); refresh(); } },
      'quitApp:': { types: ['void', ['id']], implementation: function (s) { get('/api/tray?do=quit'); app.terminate(null); } },
      'tick:': { types: ['void', ['id']], implementation: function (t) { refresh(); } },
      'pickServer:': { types: ['void', ['id']], implementation: function (s) {
        var i = s.tag;
        var name = (i >= 0 && i < names.length) ? names[i] : '';
        get('/api/tray?do=select&name=' + encodeURIComponent(name)); refresh(); } },
      'refreshSub:': { types: ['void', ['id']], implementation: function (s) { get('/api/tray?do=refresh'); } },
      'toggleRu:': { types: ['void', ['id']], implementation: function (s) {
        get('/api/tray?do=directru&on=' + (miRu && miRu.state === 1 ? '0' : '1')); refresh(); } }
    }
  });
  var target = $.VPNAutoMenuTarget.alloc.init;

  function mi(title, action) {
    var m = $.NSMenuItem.alloc.initWithTitleActionKeyEquivalent(title, action, '');
    if (action) m.setTarget(target); else m.setEnabled(false);
    return m;
  }
  var menu = $.NSMenu.alloc.init;
  menu.setAutoenablesItems(false);
  miStatus = mi('NETtool', null);
  miServer = mi('…', null);
  miToggle = mi('Включить VPN', 'toggle:');
  menu.addItem(miStatus);
  menu.addItem(miServer);
  menu.addItem($.NSMenuItem.separatorItem);
  menu.addItem(mi('Открыть NETtool', 'openUI:'));
  menu.addItem(miToggle);
  srvMenu = $.NSMenu.alloc.initWithTitle('Серверы');
  srvMenu.setAutoenablesItems(false);
  var miSrv = mi('Серверы VPN', null);
  miSrv.setEnabled(true);
  miSrv.setSubmenu(srvMenu);
  menu.addItem(miSrv);
  menu.addItem($.NSMenuItem.separatorItem);
  menu.addItem(mi('Выход', 'quitApp:'));
  item.setMenu(menu);

  refresh();
  $.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(2.0, target, 'tick:', null, true);
  app.run;
}
