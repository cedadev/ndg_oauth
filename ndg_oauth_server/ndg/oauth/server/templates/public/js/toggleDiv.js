// JavaScript Document
function toggleDiv(){ //v1.4 by PVII
    
    var i,x,tB,j=0,tA=new Array(),arg=toggleDiv.arguments;

    if(document.getElementsByTagName)  
    {
        for(i=4;i<arg.length;i++)
        {
            
            tB=document.getElementsByTagName(arg[i]);
            
            for(x=0;x<tB.length;x++)
            {
                tA[j]=tB[x];
                
                j++;
            }
        }

        for(i=0;i<tA.length;i++)
        {
            //alert(tA[i].className);
            
            //if (tA[i].className!='abstractText_shown' || tA[i].className!='abstractText_hidden')
            //{
                if(tA[i].className)
                {
                
                    if(tA[i].id==arg[1])
                    {
                        if(arg[0]==1)
                        {
                            tA[i].className=(tA[i].className==arg[3])?arg[2]:arg[3];
                        }
                        else{tA[i].className=arg[2];
                        }
                    }
                    else if(arg[0]==1 && arg[1]=='none')
                    {
                        if(tA[i].className==arg[2] || tA[i].className==arg[3])
                        {
                            tA[i].className=(tA[i].className==arg[3])?arg[2]:arg[3];
                        }
                    }else if(tA[i].className==arg[2])
                    {
                        tA[i].className=arg[3];
                    }
                }
            //}                     
        }
    }
}


function Div_hide(pass) { 

    var divs = document.getElementsByTagName('div'); 

    for(i=0;i<divs.length;i++)
    { 
        if(divs[i].id.match(pass))
        {
            //if they are 'see' divs 
            if (document.getElementById) // DOM3 = IE5, NS6 
                divs[i].style.display = "none";// show/hide 
            else 
                if (document.layers) // Netscape 4 
                    document.layers[divs[i]].display = "none";
                else // IE 4 
                    document.all.hideShow.divs[i].display = "none"; 
        } 
    } 
} 

function Div_show(pass) { 

    var divs = document.getElementsByTagName('div'); 
    
    for(i=0;i<divs.length;i++)
    { 
        if(divs[i].id.match(pass))
        { 
            if (document.getElementById) 
                divs[i].style.display="block"; 
            else 
                if (document.layers) // Netscape 4 
                    document.layers[divs[i]].display="block"; 
            else // IE 4 
                document.all.hideShow.divs[i].display="block";
        } 
    } 
} 

function span_hide(pass) { 

    var divs = document.getElementsByTagName('span'); 

    for(i=0;i<divs.length;i++)
    { 
        if(divs[i].id.match(pass))
        {
            //if they are 'see' divs 
            if (document.getElementById) // DOM3 = IE5, NS6 
                divs[i].style.display = "none";// show/hide 
            else 
                if (document.layers) // Netscape 4 
                    document.layers[divs[i]].display = "none";
                else // IE 4 
                    document.all.hideShow.divs[i].display = "none"; 
        } 
    } 
} 

function span_show(pass) { 

    var divs = document.getElementsByTagName('span'); 
    
    for(i=0;i<divs.length;i++)
    { 
        if(divs[i].id.match(pass))
        { 
            if (document.getElementById) 
                divs[i].style.display="block"; 
            else 
                if (document.layers) // Netscape 4 
                    document.layers[divs[i]].display="block"; 
            else // IE 4 
                document.all.hideShow.divs[i].display="block";
        } 
    } 
}

function removeSelection(selection) {

    //simple function to remove contents of prior input    
    document.getElementById(selection).innerHTML='';
  
    //thisNode = document.getElementById(selection);
    //thisNode.removeNode(true);
    //selection.parentNode.removeChild(selection)

}




