// implement utility class no drig
import {Handle, Position} from "@xyflow/react";
import { useCFGNodeStore } from '../../store/cfgNodeStore';

const CFGNode = ({data}) => {
    const { togglePanel, activePanel } = useCFGNodeStore();
    const isActive = activePanel === data.src;

    const highlightClass = isActive
        ? 'node-selected node-layer'
        : data.isEntry
            ? 'node-entry'
            : data.isMajor
                ? 'node-major'
                : '';

    return (
        <div className={`node-base nodrag w-40 h-20 cursor-pointer transition-all duration-300 ease-out ${highlightClass}`} onClick={() => togglePanel(data.src)}> 
            <div className="node-content"> 
                <div className="node-layer node-layer-visible">
                    <div className="flex flex-col justify-center items-center w-full px-2 py-1">
                        <span className="FuncName w-full text-center pt-1">{data.name}</span>
                        <div className="border-b border-node-border w-full mx-2"></div>
                        <span className="address w-full text-center pt-1">{data.src}</span>
                        <div className="border-b border-node-border w-full mx-2"></div>
                        <span className="type w-full text-center pt-1">{data.type}</span>
                    </div>
                </div>
            </div>
             {/* Handles for connections - each side has source + target */}                                                                                                                                                                                  
            <Handle type="target" position={Position.Top} id="top-target" />                                                                                                                                                                                 
            <Handle type="source" position={Position.Top} id="top-source" />                                                                                                                                                                                 
            <Handle type="target" position={Position.Bottom} id="bottom-target" />                                                                                                                                                                           
            <Handle type="source" position={Position.Bottom} id="bottom-source" />                                                                                                                                                                           
            <Handle type="target" position={Position.Left} id="left-target" />                                                                                                                                                                               
            <Handle type="source" position={Position.Left} id="left-source" />                                                                                                                                                                               
            <Handle type="target" position={Position.Right} id="right-target" />                                                                                                                                                                             
            <Handle type="source" position={Position.Right} id="right-source" />
        </div>        
    );
};

export default CFGNode;