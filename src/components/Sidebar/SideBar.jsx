import { LuBinary } from "react-icons/lu";
import { RiSignalTowerFill } from "react-icons/ri";
import { TbBinaryTree } from "react-icons/tb";
import { TbAnalyze } from "react-icons/tb";
import { IoIosDownload } from "react-icons/io";



const SideBar = () => { 
    return (
    <div className="fixed top-0 left-0 h-screen w-16 m-0 flex flex-col items-center py-6 gap-y-3 bg-secondary text-text-primary text-shadow-lg">
        <SideBarIcon icon={<LuBinary size="32"/>} text={"Binary Overview"}/>
        <SideBarIcon icon={<RiSignalTowerFill size="32"/>} text={"Triage Signals"}/>
        <SideBarIcon icon={<TbBinaryTree size="32"/>} text={"Graph Toggles"}/>

        <SideBarIcon icon={<TbAnalyze size="32"/>} text={"Analysis Status"}/>
        <SideBarIcon icon={<IoIosDownload size="32"/>} text={"Download Binary inforamation"}/>
    </div>);
};


const SideBarIcon =({ icon, text, }) => (
    <div className="sidebar-icon group">
        { icon }

        <span className="sidebar-tooltip group-hover:scale-100">
            {text}
        </span>
    </div>
);
export default SideBar;