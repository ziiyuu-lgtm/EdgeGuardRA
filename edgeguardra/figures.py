"""Regenerate exact manuscript graphics from a chosen functional snapshot."""
from pathlib import Path
import json


def make_figures(summary_path, out_dir):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    figdir = Path(out_dir)
    figdir.mkdir(parents=True, exist_ok=False)
    fig, ax = plt.subplots(figsize=(12, 5.1))
    ax.set_xlim(-.1, 12); ax.set_ylim(0, 5.1); ax.axis('off')

    def box(x,y,title,detail,color='#eaf1f8'):
        ax.add_patch(FancyBboxPatch((x,y),2.55,1.05,boxstyle='round,pad=0.12,rounding_size=0.12',
                                    linewidth=1,edgecolor='#315370',facecolor=color))
        ax.text(x+1.275,y+.72,title,ha='center',va='center',fontsize=11,fontweight='bold',color='#18354b')
        ax.text(x+1.275,y+.34,detail,ha='center',va='center',fontsize=9,color='#333333',linespacing=1.15)

    def arrow(a,b):
        ax.annotate('',xy=b,xytext=a,arrowprops={'arrowstyle':'->','color':'#596b7b','lw':1.6})

    box(.1,3.15,'Candidate proposal','Scripted agent / optional LLM','#eef5fb')
    box(3.05,3.15,'Trusted wrapper','Identity, nonce and HMAC','#eef5fb')
    box(6,3.15,'Policy gate','Authenticate, authorize, triage','#d8ebf6')
    box(9,3.15,'Simulated broker','Recheck; one-time execution','#e3f3ed')
    box(.1,.65,'Signed evidence','Source key + device grant','#fff2dc')
    box(3.05,.65,'Evidence ingestor','Verify time, grant and nonce','#fff2dc')
    box(6,.65,'Shared SQLite state','Context, decisions, nonces, log','#f0eef8')
    box(9,.65,'Review key','Scoped grant + challenge','#fff2dc')
    for a,b in [((2.77,3.67),(2.97,3.67)),((5.72,3.67),(5.92,3.67)),((8.67,3.67),(8.92,3.67)),
                ((2.77,1.17),(2.97,1.17)),((5.72,1.17),(5.92,1.17)),((7.28,1.82),(7.28,3.05)),
                ((9.10,1.82),(8.35,3.05))]: arrow(a,b)
    ax.text(6,0.08,'Trusted operator controls keys, policy, clock and database. No physical actuator is connected.',
            ha='center',va='center',fontsize=9,color='#444444')
    fig.tight_layout(pad=.5); fig.savefig(figdir/'architecture.png',dpi=220,bbox_inches='tight'); plt.close(fig)

    summary=json.loads(Path(summary_path).read_text(encoding='utf-8'))
    labels=['Unguarded','Schema only','Capability','Risk-aware']
    modes=['unguarded','schema','capability','risk']
    fig,ax=plt.subplots(figsize=(9,3.9)); left=[0]*4
    for outcome,color in [('allow','#2c8c75'),('block','#c05454'),('defer','#c49231')]:
        values=[summary['results'][mode][outcome] for mode in modes]
        bars=ax.barh(labels,values,left=left,color=color,label=outcome.title(),height=.58)
        for bar,val,offset in zip(bars,values,left):
            if val: ax.text(offset+val/2,bar.get_y()+bar.get_height()/2,str(val),ha='center',va='center',color='white',fontweight='bold',fontsize=10)
        left=[a+b for a,b in zip(left,values)]
    ax.invert_yaxis();ax.set_xlim(0,51);ax.set_xlabel('Synthetic cases per condition')
    ax.set_title('Designed triage outcomes (51 cases per condition)',loc='left',fontweight='bold')
    ax.legend(ncol=3,loc='upper center',bbox_to_anchor=(.5,-.23),frameon=False)
    ax.spines[['top','right']].set_visible(False); ax.grid(axis='x',alpha=.18);ax.set_axisbelow(True)
    fig.tight_layout();fig.savefig(figdir/'outcomes.png',dpi=220,bbox_inches='tight');plt.close(fig)
    return [str(figdir / 'architecture.png'), str(figdir / 'outcomes.png')]
