#include "binaryninjaapi.h"
#include "uitypes.h"
#include "uicontext.h"
//#include "ui/sidebar.h"
//#include <QImage>

extern "C" {
    // Tells Binary Ninja which version of the API you compiled against
    BN_DECLARE_UI_ABI_VERSION

    // Function run on plugin startup, do simple initialization here (ViewTypes, SidebarWidgetTypes, etc)
    BINARYNINJAPLUGIN bool UIPluginInit()
    {
        //Sidebar::addSidebarWidgetType(new DebuggerWidgetType(QImage(":/debugger/debugger"), "Debugger"));
        return true;
    }

    // (Optional) Function to add other plugin dependencies in case your plugin requires them
    // Historically, these have never actually been used 
    BINARYNINJAPLUGIN void UIPluginDependencies()
    {
        // For example, if you require triage view to be loaded before your plugin
        //AddRequiredUIPluginDependency("triage");
    }
}
